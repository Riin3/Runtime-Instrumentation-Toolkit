import pymem
import logging
import os
import sys
import time

# 将主目录添加到sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.advanced_scanner import AdvancedScanner
from core.structure_manager import StructureManager
from core.code_cave_hooker import CodeCaveHooker
from pymem.exception import ProcessNotFound

# --- 配置 ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
PROCESS_NAME = "Tutorial-x86_64.exe"
DEFINITIONS_FILE = "definitions.yaml"
HOOK_NAME = "PlayerBaseHook"

def main():
    """
    一个完整的端到端测试，用于验证 CodeCaveHooker 的功能。
    它将自动完成：
    1. 找到要监视的地址（生命值）。
    2. 安装一个Code Cave钩子来捕获访问该地址的`this`指针。
    3. 验证捕获到的指针。
    4. 安全地卸载钩子并清理。
    """
    try:
        pm = pymem.Pymem(PROCESS_NAME)
    except ProcessNotFound:
        logging.error(f"错误: 未找到进程 '{PROCESS_NAME}'。请先运行该程序。")
        return

    # 1. 初始化核心组件
    scanner = AdvancedScanner(pm)
    structure_manager = StructureManager(pm, scanner, DEFINITIONS_FILE)
    hooker = CodeCaveHooker(pm, scanner)

    logging.info("--- 步骤 1: 解析要监视的地址 ---")
    
    # 我们需要一个地址来监视，这里用指针路径找到health地址
    player_def = structure_manager.get_definition("TutorialPlayer")
    if not player_def:
        logging.error("在definitions.yaml中未找到'TutorialPlayer'的定义。")
        return

    health_finder = player_def.get("bootstrap_finder")
    if not health_finder:
        logging.error("在definitions.yaml中未找到TutorialPlayer的bootstrap_finder。")
        return
        
    watch_address = structure_manager._resolve_pointer_path(health_finder)
    if not watch_address:
        logging.error("无法解析得到要监视的health地址。")
        return
    logging.info(f"成功解析到要监视的地址: {hex(watch_address)}")

    try:
        logging.info("\n--- 步骤 2: 安装 Code Cave 钩子 ---")
        success = hooker.install_hook_for_address(watch_address, HOOK_NAME)
        if not success:
            logging.error("安装钩子失败，测试终止。")
            return

        logging.info("\n--- 步骤 3: 等待并获取捕获的指针 ---")
        logging.info("钩子已安装。请在教程程序中执行会导致生命值变化的操作（例如：被攻击）。")
        logging.info("将每秒检查一次，持续30秒...")

        captured_pointer = 0
        for i in range(30):
            captured_pointer = hooker.get_captured_pointer(HOOK_NAME)
            if captured_pointer:
                logging.info(f"成功捕获到指针！地址: {hex(captured_pointer)}")
                break
            time.sleep(1)
            print(".", end="", flush=True)

        logging.info("\n\n--- 步骤 4: 验证结果 ---")
        if captured_pointer:
            logging.info(f"测试成功: 捕获到的指针是一个有效的地址 {hex(captured_pointer)}。")
            # 在一个真实的游戏中，这个地址应该是一个指向某个模块内部的合理值
            # 这里的简单检查只是确保它不是0
        else:
            logging.error("测试失败: 超时仍未捕获到指针。")

    except Exception as e:
        logging.error(f"测试过程中发生未知错误: {e}", exc_info=True)
    
    finally:
        logging.info("\n--- 步骤 5: 清理和卸载 ---")
        hooker.uninstall_hook(HOOK_NAME)
        logging.info("测试结束。")


if __name__ == "__main__":
    main() 