import os
import sys
import logging
import pymem

# 将主目录添加到sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.advanced_scanner import AdvancedScanner
from pymem.exception import ProcessNotFound

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# 我们在之前的运行中发现的、包含关键LEA指令的地址
# 我们将为这个地址生成一个新的、高效的AOB
INSTRUCTION_ADDRESS_TO_SCAN = 0x7ffdd7c494e7

def main():
    """
    该脚本的唯一目的是为GameObjectManager的静态指针LEA指令生成一个简短、唯一的AOB。
    """
    try:
        pm = pymem.Pymem("Yokai Art.exe")
    except ProcessNotFound:
        logging.error("错误: 未找到进程 'Yokai Art.exe'。请先运行游戏。")
        return

    scanner = AdvancedScanner(pm)

    logging.info(f"将为关键指令地址 {hex(INSTRUCTION_ADDRESS_TO_SCAN)} 生成一个新的AOB特征码。")
    
    # 调用 generate_pattern 为关键指令生成模式
    # 我们使用稍大的size和较短的min_length来确保能找到一个紧凑的模式
    pattern_result = scanner.generate_pattern(INSTRUCTION_ADDRESS_TO_SCAN, size=128, min_length=12)
    
    if not pattern_result:
        logging.error("无法为关键指令生成唯一的AOB。")
        return
        
    pattern_bytes, readable_pattern = pattern_result
    
    logging.info("="*50)
    logging.info(f"成功生成新的AOB: {readable_pattern}")
    logging.info("请将这个新的AOB更新到你的配置文件或代码中，以供将来使用。")
    logging.info("="*50)

if __name__ == "__main__":
    main() 