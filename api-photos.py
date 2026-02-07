import os
import requests
import time
import concurrent.futures
import logging
import hashlib
import uuid
import threading
from tqdm import tqdm
from urllib.parse import urlparse

try:
    from PIL import Image
    from io import BytesIO
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False
    logging.warning(" 未安装Pillow库（pip install pillow），将仅校验文件头，无法验证图片完整性")

# ===================== 全局配置（可自定义） =====================
MAX_THREADS = 50  # 最大并发线程数（防止输入过大）
CONNECT_TIMEOUT = 10  # 连接超时时间（秒）
INIT_READ_TIMEOUT = 30  # 初始读取超时（秒）
READ_TIMEOUT_STEP = 15  # 重试时读取超时递增步长（秒）
RETRY_TIMES = 3  # 下载失败重试次数
HASH_CHUNK_SIZE = 8192  # 哈希计算分块大小
DOWNLOAD_CHUNK_SIZE = 1024 * 32  # 分块下载大小（32KB）
PAUSE_PROMPT = "\n 操作提示：按 p 暂停 | r 恢复 | q 退出\n" 
RETRY_STATUS_CODES = {408, 500, 502, 503, 504, 429}  
# 图片文件头特征（用于快速校验）
IMAGE_MAGIC_NUMBERS = {
    b'\xFF\xD8\xFF': '.jpg',  # JPG/JPEG
    b'\x89\x50\x4E\x47\x0D\x0A\x1A\x0A': '.png',  # PNG
    b'\x47\x49\x46\x38': '.gif',  # GIF
    b'\x52\x49\x46\x46': '.webp'  # WebP (RIFF开头)
}
# ================================================================

# 全局控制变量
pause_event = threading.Event()
exit_flag = threading.Event()
pause_event.set()

class TqdmHandler(logging.Handler):
    """适配tqdm进度条的日志处理器"""
    def emit(self, record):
        try:
            msg = self.format(record)
            tqdm.write(msg)
        except Exception:
            self.handleError(record)

# 配置日志
log = logging.getLogger(__name__)
log.setLevel(logging.INFO)
if log.handlers:
    log.handlers.clear()
handler = TqdmHandler()
formatter = logging.Formatter(
    '%(asctime)s [%(levelname)s] [%(threadName)s] %(message)s',
    '%Y-%m-%d %H:%M:%S'
)
handler.setFormatter(formatter)
log.addHandler(handler)

# 创建全局requests会话
session = requests.Session()
session.headers.update({
    'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36',
    'Accept': 'image/webp,image/jpeg,image/png,*/*',
    'Accept-Encoding': 'gzip, deflate',
    'Connection': 'keep-alive'
})

def input_listener():
    """监听用户输入，处理暂停/恢复/退出指令"""
    while not exit_flag.is_set():
        try:
            user_input = input().strip().lower()
            if user_input == 'p':
                pause_event.clear()
                log.info(" 已暂停下载，按 r 恢复")
            elif user_input == 'r':
                pause_event.set()
                log.info(" 已恢复下载")
            elif user_input == 'q':
                exit_flag.set()
                pause_event.set()
                log.warning(" 用户触发退出，正在终止所有任务...")
            else:
                log.warning(f"未知指令：{user_input}，请输入 p/r/q")
        except (EOFError, KeyboardInterrupt):
            exit_flag.set()
            pause_event.set()
            log.warning(" 检测到中断信号，正在退出...")
            break

def calculate_content_hash(content):
    """计算图片内容的MD5哈希（去重核心）"""
    md5 = hashlib.md5()
    for i in range(0, len(content), HASH_CHUNK_SIZE):
        chunk = content[i:i + HASH_CHUNK_SIZE]
        md5.update(chunk)
    return md5.hexdigest()

def validate_image_content(content):
    """校验图片内容合法性"""
    if len(content) < 8:
        return False, "", "文件内容过短（小于8字节）"
    
    # 校验文件头
    detected_ext = ""
    for magic, ext in IMAGE_MAGIC_NUMBERS.items():
        if content.startswith(magic):
            detected_ext = ext
            break
    if not detected_ext:
        try:
            content.decode('utf-8')
            return False, "", "内容为文本（非图片，可能是API错误信息）"
        except:
            return False, "", f"未知图片格式（文件头：{content[:8].hex()}）"
    
    # PIL完整性校验
    if PIL_AVAILABLE:
        try:
            img = Image.open(BytesIO(content))
            img.verify()
            img = Image.open(BytesIO(content))
            width, height = img.size
            log.debug(f" 图片校验通过 | 格式={detected_ext} | 尺寸={width}x{height}")
            return True, detected_ext, ""
        except Exception as e:
            return False, detected_ext, f"图片损坏（PIL校验失败）：{str(e)[:50]}"
    
    return True, detected_ext, ""

def download_image_chunked(url, timeout):
    """分块下载图片（适配慢加载/大图片）"""
    try:
        response = session.get(
            url, 
            timeout=timeout,
            stream=True,
            allow_redirects=True
        )
        response.raise_for_status()
        
        if response.status_code in RETRY_STATUS_CODES:
            log.warning(f" 遇到可重试状态码：{response.status_code}，将重试")
            return None
        
        # 分块读取内容
        image_content = bytearray()
        for chunk in response.iter_content(chunk_size=DOWNLOAD_CHUNK_SIZE):
            if exit_flag.is_set():
                return None
            pause_event.wait()
            
            if chunk:
                image_content.extend(chunk)
        
        if not image_content:
            log.warning(f" 下载内容为空 | URL={url}")
            return None
        
        return bytes(image_content)
    
    except requests.exceptions.ConnectTimeout:
        log.warning(f" 连接超时（{timeout[0]}秒）| URL={url}")
        return None
    except requests.exceptions.ReadTimeout:
        log.warning(f" 读取超时（{timeout[1]}秒）| URL={url}（慢加载？）")
        return None
    except requests.exceptions.HTTPError as e:
        if e.response.status_code in RETRY_STATUS_CODES:
            log.warning(f" HTTP错误 {e.response.status_code} | URL={url}，将重试")
            return None
        log.error(f" 不可重试HTTP错误 {e.response.status_code} | URL={url}")
        return None
    except requests.exceptions.RequestException as e:
        log.warning(f" 请求异常 | 错误={e} | URL={url}")
        return None
    except Exception as e:
        log.error(f" 分块下载异常 | 错误={e} | URL={url}")
        return None

def download_single_task(url, directory, progress_bar, hash_set):
    """单个下载任务（供线程池调用）"""
    # 检查退出标志
    if exit_flag.is_set():
        progress_bar.update(1)
        return False
    
    for retry in range(RETRY_TIMES + 1):
        if exit_flag.is_set():
            progress_bar.update(1)
            return False
        pause_event.wait()
        
        # 计算当前超时时间
        current_read_timeout = INIT_READ_TIMEOUT + (retry * READ_TIMEOUT_STEP)
        timeout = (CONNECT_TIMEOUT, current_read_timeout)
        
        try:
            image_content = download_image_chunked(url, timeout)
            if image_content is None:
                if retry >= RETRY_TIMES:
                    log.error(f" 任务失败：多次重试超时 | URL={url}")
                    progress_bar.update(1)
                    return False
                wait_time = 1 * (2 ** retry)
                log.info(f" 第{retry+1}次重试失败，等待{wait_time}秒后重试 | URL={url}")
                time.sleep(wait_time)
                continue
            
            is_valid, detected_ext, error_msg = validate_image_content(image_content)
            if not is_valid:
                log.warning(f" 任务失败：图片非法 | 原因={error_msg} | 重试次数={retry+1}")
                if retry >= RETRY_TIMES:
                    log.error(f" 任务最终失败：图片校验不通过 | URL={url}")
                    progress_bar.update(1)
                    return False
                wait_time = 1 * (2 ** retry)
                log.info(f" 图片非法，等待{wait_time}秒后重试 | URL={url}")
                time.sleep(wait_time)
                continue
            
            image_hash = calculate_content_hash(image_content)
            if image_hash in hash_set:
                log.info(f" 任务完成：跳过重复图片 | 哈希={image_hash}")
                progress_bar.update(1)
                return True  
            
            filename = f"{uuid.uuid4()}{detected_ext}"
            filepath = os.path.join(directory, filename)
            
            with open(filepath, 'wb', buffering=DOWNLOAD_CHUNK_SIZE) as f:
                f.write(image_content)
            
            try:
                if PIL_AVAILABLE:
                    img = Image.open(filepath)
                    img.load()
            except Exception as e:
                os.remove(filepath)
                log.error(f" 保存后校验失败，已删除损坏文件 | 路径={filepath} | 原因={e}")
                if retry >= RETRY_TIMES:
                    progress_bar.update(1)
                    return False
                wait_time = 1 * (2 ** retry)
                log.info(f" 保存后文件损坏，等待{wait_time}秒后重试 | URL={url}")
                time.sleep(wait_time)
                continue
            
            hash_set.add(image_hash)
            log.info(f" 任务完成：保存成功 | 文件={filepath} | 大小={len(image_content)/1024:.2f}KB | 哈希={image_hash}")
            progress_bar.update(1)
            return True
        
        except Exception as e:
            log.error(f" 任务失败：未知错误 | 错误={e} | URL={url}")
            progress_bar.update(1)
            return False

def validate_inputs(directory, num_threads, total_downloads, url):
    """输入校验（语义更清晰）"""
    try:
        test_file = os.path.join(directory, f"test_{uuid.uuid4()}.tmp")
        with open(test_file, 'w') as f:
            f.write('test')
        os.remove(test_file)
    except PermissionError:
        raise ValueError(f"目录 {directory} 无写入权限")
    except Exception as e:
        raise ValueError(f"目录校验失败：{e}")
    
    if num_threads <= 0:
        raise ValueError("并发线程数必须>0")
    num_threads = min(num_threads, MAX_THREADS)  # 限制最大线程数
    
    if total_downloads <= 0:
        raise ValueError("总下载次数必须>0")
    
    parsed_url = urlparse(url)
    if not (parsed_url.scheme and parsed_url.netloc):
        raise ValueError("URL格式无效（需包含http/https，如：https://xxx.jpg）")
    
    return num_threads

def download_images(url, directory, num_threads, total_downloads):
    """
    主下载逻辑（语义清晰版）
    :param url: 图片URL
    :param directory: 保存目录
    :param num_threads: 并发线程数（用多少个线程）
    :param total_downloads: 总下载次数（总共下载多少次，去重前）
    """
    downloaded_hashes = set()
    
    listener_thread = threading.Thread(target=input_listener, daemon=True)
    listener_thread.start()
    log.info(PAUSE_PROMPT)
    
    with tqdm(total=total_downloads, desc="📥 下载进度", unit="次") as pbar:
        if exit_flag.is_set():
            pbar.close()
            return
        
        tasks = [url] * total_downloads
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as executor:
            future_to_task = {
                executor.submit(download_single_task, url, directory, pbar, downloaded_hashes): idx
                for idx, url in enumerate(tasks)
            }
            
            for future in concurrent.futures.as_completed(future_to_task):
                if exit_flag.is_set():
                    executor.shutdown(wait=False, cancel_futures=True)
                    log.warning(" 已终止剩余任务")
                    break
    
    if not exit_flag.is_set():
        total_skipped = total_downloads - len(downloaded_hashes)
        log.info(f"\n 下载统计：")
        log.info(f"   - 总任务数：{total_downloads} 次")
        log.info(f"   - 实际保存：{len(downloaded_hashes)} 张（去重后）")
        log.info(f"   - 跳过重复：{total_skipped} 次")
    else:
        log.info(f"\n 强制退出统计：")
        log.info(f"   - 已完成任务：{pbar.n} 次")
        log.info(f"   - 实际保存：{len(downloaded_hashes)} 张（去重后）")
    
    exit_flag.set()
    listener_thread.join(timeout=1)

def main():
    """主函数（交互式输入，语义更清晰）"""
    print("===== 多线程图片下载工具（清晰版） =====")
    if not PIL_AVAILABLE:
        print("\n 建议安装Pillow库以启用完整的图片完整性校验：pip install pillow\n")
    
    try:
        directory = input("\n 请输入保存目录（绝对路径）: ").strip()
        if not directory:
            raise ValueError("目录不能为空")
        os.makedirs(directory, exist_ok=True)
        
        url = input(" 请输入图片URL: ").strip()
        if not url:
            raise ValueError("URL不能为空")
        
        num_threads = int(input(" 请输入并发线程数（建议10以内）: ").strip())
        total_downloads = int(input(" 请输入总下载次数（总共要下载多少次）: ").strip())
        
        num_threads = validate_inputs(directory, num_threads, total_downloads, url)
        
        pause_event.set()
        exit_flag.clear()
        
        # 开始下载
        print(f"\n 开始下载（防损坏+慢加载适配+暂停+去重）：")
        print(f"   - 图片URL: {url}")
        print(f"   - 保存目录: {directory}")
        print(f"   - 并发线程数: {num_threads} 个")
        print(f"   - 总下载次数: {total_downloads} 次（去重前）")
        download_images(url, directory, num_threads, total_downloads)
        
        print("\n 下载任务结束！")
        
    except ValueError as e:
        log.error(f" 输入错误：{e}")
    except Exception as e:
        log.error(f" 程序异常：{e}", exc_info=True)
    finally:
        exit_flag.set()
        pause_event.set()

if __name__ == "__main__":
    main()

