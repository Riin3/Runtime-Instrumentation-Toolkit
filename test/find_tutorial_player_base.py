import pymem
import logging
import os
import sys

# 将主目录添加到sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.advanced_scanner import AdvancedScanner
from core.structure_manager import StructureManager
from pymem.exception import ProcessNotFound

# --- 配置 ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
PROCESS_NAME = "Tutorial-x86_64.exe"
DEFINITIONS_FILE = "definitions.yaml"

def main():
    """
    使用现代化的 StructureManager.build_from_hook 方法，
    通过硬件断点全自动寻找 TutorialPlayer 的基地址。
    """
    try:
        pm = pymem.Pymem(PROCESS_NAME)
    except ProcessNotFound:
        logging.error(f"错误: 未找到进程 '{PROCESS_NAME}'。请先运行该程序。")
        return

    # 1. 初始化核心组件
    scanner = AdvancedScanner(pm)
    structure_manager = StructureManager(pm, scanner, DEFINITIONS_FILE)

    logging.info("组件初始化完毕，开始执行 build_from_hook...")

    # 2. 调用核心方法
    # 这一步会自动完成：
    # - 解析 definitions.yaml 中的 'TutorialPlayer'
    # - 找到 bootstrap_finder，发现其类型是 'pointer_path'
    # - 解析指针路径 "Tutorial-x86_64.exe" + 0x10A60 -> +0x8 -> +0x4，得到health地址
    # - 在 health 地址上设置硬件断点
    # - 等待游戏代码写入该地址
    # - 从CPU上下文中捕获 RCX (this指针/基地址) 和 RIP (指令地址)
    # - 自动移除断点
    # - 返回捕获到的基地址
    base_address = structure_manager.build_from_hook("TutorialPlayer")

    # 3. 验证结果
    if base_address:
        logging.info("=" * 60)
        logging.info(f"测试成功！")
        logging.info(f"通过全自动硬件断点捕获到的玩家基地址是: {hex(base_address)}")
        logging.info("=" * 60)
        
        # 我们可以用这个基地址创建一个结构体实例来进一步交互
        player = structure_manager.build_from_base_address("TutorialPlayer", base_address)
        if player:
            try:
                health = player.health
                mana = player.mana
                logging.info(f"成功读取玩家状态 -> 生命值: {health}, 魔法值: {mana}")

                logging.info("尝试写入新的生命值: 999")
                player.health = 999
                new_health = player.health
                logging.info(f"回读生命值: {new_health}")
                if new_health == 999:
                    logging.info("写入和回读验证成功！")
                else:
                    logging.error("写入验证失败！")

            except AttributeError as e:
                logging.error(f"读取或写入玩家状态失败: {e}")
        else:
            logging.error("无法根据捕获到的基地址创建玩家实例。")
    else:
        logging.error("=" * 60)
        logging.error("测试失败: build_from_hook未能返回有效的基地址。")
        logging.error("请确保：")
        logging.error("  1. 'definitions.yaml' 中的指针路径正确。")
        logging.error("  2. 在程序运行时，执行了会改变生命值的操作（例如被攻击）。")
        logging.error("=" * 60)

if __name__ == "__main__":
    main() 