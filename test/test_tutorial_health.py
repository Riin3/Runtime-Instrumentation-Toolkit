import pymem
import logging
import os
import sys

# 将主目录添加到sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from pymem.exception import ProcessNotFound

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

PROCESS_NAME = "Tutorial-x86_64.exe"
HEALTH_ADDRESS = 0x03687CD8

def main():
    """
    初级测试脚本：
    1. 附加到 Tutorial-x86_64.exe 进程。
    2. 读取指定的动态生命值地址。
    3. 打印读取到的值。
    这个脚本只进行读操作，确保绝对安全。
    """
    try:
        pm = pymem.Pymem(PROCESS_NAME)
        logging.info(f"成功附加到进程: {PROCESS_NAME}")
    except ProcessNotFound:
        logging.error(f"错误: 未找到进程 '{PROCESS_NAME}'。请先运行初级测试程序。")
        return
        
    try:
        health_value = pm.read_int(HEALTH_ADDRESS)
        logging.info("="*50)
        logging.info(f"成功从地址 {hex(HEALTH_ADDRESS)} 读取到生命值: {health_value}")
        logging.info("="*50)
    except Exception as e:
        logging.error(f"读取地址 {hex(HEALTH_ADDRESS)} 时发生错误: {e}", exc_info=True)
        logging.error("请确认地址是否正确，以及程序是否仍在运行。")

if __name__ == "__main__":
    main() 