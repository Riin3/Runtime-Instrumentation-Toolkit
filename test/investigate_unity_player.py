import pymem
from pymem.exception import ProcessNotFound
import logging
import os
import sys
import time

# 将主目录添加到sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.advanced_scanner import AdvancedScanner

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# 我们通过 generate_gomanager_aob.py 生成的、指向关键LEA指令的全新AOB
UNITY_GAMEMANAGER_AOB = "8B C9 85 D2 75 21 48 8B 05 72 84 B5"

def main():
    try:
        pm = pymem.Pymem("Yokai Art.exe")
        logging.info("成功附加到进程: Yokai Art.exe")
    except ProcessNotFound:
        logging.error("错误: 未找到进程 'Yokai Art.exe'。请先运行游戏。")
        return

    scanner = AdvancedScanner(pm)
    
    logging.info(f"正在全内存中扫描GameObjectManager的新AOB: {UNITY_GAMEMANAGER_AOB}")
    # 我们之前的模块扫描失败了，现在尝试全内存扫描
    addresses = scanner.aob_scan(UNITY_GAMEMANAGER_AOB, scan_mode='full')
    
    if not addresses:
        logging.error("全内存扫描失败，仍然未找到AOB匹配项。这不应该发生。")
        return
        
    manager_instruction_address = addresses[0]
    logging.info(f"成功找到指令地址: {hex(manager_instruction_address)}")

    # 这条指令是 LEA RCX, [RIP + offset]
    # 我们需要解析出 RIP 相对地址
    try:
        # read_int 在这里读取的是指令的一部分，即相对偏移
        # instruction_offset=3, instruction_size=7 是 LEA 指令的典型格式
        static_ptr_address = scanner.resolve_rip_relative_address(manager_instruction_address, 3, 7)
        
        logging.info(f"成功解析出静态地址 A: {hex(static_ptr_address)}")
        
        # 第一次解引用，获取中间指针
        intermediate_ptr_obj = pm.read_longlong(static_ptr_address)
        intermediate_ptr = int(intermediate_ptr_obj)
        logging.info(f"读取地址 A 得到中间指针 B: {hex(intermediate_ptr)}")

        if not intermediate_ptr:
            logging.error("中间指针 B 为空，无法继续解引用。")
            return

        # 第二次解引用，获取最终的GameObjectManager实例地址
        manager_instance_obj = pm.read_longlong(intermediate_ptr)
        manager_instance = int(manager_instance_obj)
        logging.info(f"读取地址 B 得到最终实例 C: {hex(manager_instance)}")
        
        if not manager_instance:
            logging.error("最终实例 C 为空，GameObjectManager可能尚未初始化。")
            return

        logging.info("="*50)
        logging.info(f"成功！GameObjectManager 的基地址很可能是: {hex(manager_instance)}")
        
        # 尝试读取第一个指针作为验证
        try:
            first_pointer_obj = pm.read_longlong(manager_instance)
            first_pointer = int(first_pointer_obj)
            logging.info(f"验证：从基地址读取到的第一个指针是: {hex(first_pointer)}")
        except Exception as read_exc:
            logging.warning(f"无法读取基地址处的第一个指针: {read_exc}")

        logging.info("这是一个非常可靠的基地址，可以从此开始探索玩家数据。")
        logging.info("="*50)

    except Exception as e:
        logging.error(f"解析地址或读取内存时出错: {e}", exc_info=True)

if __name__ == "__main__":
    main() 