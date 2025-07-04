import pymem
import logging
import os
import sys
import time

# 将主目录添加到sys.path，以便导入核心模块
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.advanced_scanner import AdvancedScanner
from core.structure_manager import StructureManager
from core.code_cave_hooker import CodeCaveHooker
from pymem.exception import ProcessNotFound

# --- 配置 ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
PROCESS_NAME = "Tutorial-x86_64.exe"
DEFINITIONS_FILE = "definitions.yaml"
STRUCTURE_NAME = "TutorialPlayer"

def run_final_test():
    """
    最终框架的端到端测试。
    这个测试将验证我们从配置加载、AOB扫描、代码注入、指针捕获
    到最终通过高层API读写成员变量的整个流程。
    """
    pm = None
    manager = None
    try:
        logging.info(f"--- 步骤 1: 连接到进程 '{PROCESS_NAME}' ---")
        pm = pymem.Pymem(PROCESS_NAME)
        logging.info("连接成功。")
    except ProcessNotFound:
        logging.error(f"错误: 未找到进程 '{PROCESS_NAME}'。请先运行该程序。")
        return

    try:
        # --- 步骤 2: 初始化核心组件 ---
        logging.info("--- 步骤 2: 初始化核心管理器 ---")
        scanner = AdvancedScanner(pm)
        hooker = CodeCaveHooker(pm)
        manager = StructureManager(pm, scanner, hooker, DEFINITIONS_FILE)
        logging.info("所有核心组件初始化完毕。")

        # --- 步骤 3: 挂载结构体 ---
        logging.info(f"--- 步骤 3: 尝试挂载结构体 '{STRUCTURE_NAME}' ---")
        if not manager.mount(STRUCTURE_NAME):
            logging.error("挂载失败。请检查AOB定义和游戏版本。测试终止。")
            return
        logging.info("挂载请求已发送。钩子已部署。")

        # --- 步骤 4: 等待并获取实例 ---
        logging.info(f"--- 步骤 4: 等待游戏触发钩子以捕获基地址 ---")
        logging.info("请在教程程序中执行会导致生命值变化的操作（例如：被攻击）。")
        logging.info("将每秒检查一次，持续30秒...")

        player_instance = None
        for i in range(30):
            player_instance = manager.get(STRUCTURE_NAME)
            if player_instance:
                logging.info(f"成功获取到 '{STRUCTURE_NAME}' 的实例！")
                break
            time.sleep(1)
            print(".", end="", flush=True)
        
        print() # 换行

        if not player_instance:
            logging.error("测试失败: 超时仍未获取到结构体实例。")
            return

        # --- 步骤 5: 验证读写 ---
        logging.info(f"--- 步骤 5: 验证对成员 'health' 的读取 ---")
        try:
            health = player_instance.health
            logging.info(f"成功读取到玩家生命值: {health} (这是一个原始字节表示，后续可以添加类型转换)")
            # 这里可以添加对值的验证逻辑
        except Exception as e:
            logging.error(f"读取 'health' 成员时出错: {e}", exc_info=True)
            return
            
        logging.info("测试成功！整个框架按预期工作。")

    except Exception as e:
        logging.error(f"测试过程中发生未知错误: {e}", exc_info=True)
    
    finally:
        # --- 步骤 6: 清理 ---
        if manager:
            logging.info("--- 步骤 6: 卸载所有钩子并清理资源 ---")
            manager.unmount_all()
            logging.info("清理完毕。")
        
        logging.info("测试结束。")


if __name__ == "__main__":
    run_final_test() 