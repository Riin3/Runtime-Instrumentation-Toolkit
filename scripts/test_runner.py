import logging
import sys
import os
import argparse
from pymem import Pymem

sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from core.structure_manager import StructureManager

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def analyze_address(process_name: str, address: int, struct_name: str, definitions_file: str):
    """
    附加到进程，读取指定地址的结构体，并打印其内容。
    """
    try:
        pm = Pymem(process_name)
        logging.info(f"成功附加到进程: {process_name} (PID: {pm.process_id})")

        struct_manager = StructureManager(pm, definitions_file)
        
        logging.info(f"正在分析地址 {hex(address)} 的 '{struct_name}' 结构...")
        
        struct_instance = struct_manager.get_structure(struct_name, address)

        print("\n--- 结构体分析结果 ---")
        for member, (offset, type_name) in struct_instance._flat_definition.items():
            if type_name not in struct_manager.definitions:
                try:
                    value = struct_instance.read_member(member)
                    print(f"  {member} (偏移: {hex(offset)}, 类型: {type_name}): {value}")
                except Exception as e:
                    print(f"  {member} (偏移: {hex(offset)}, 类型: {type_name}): 读取错误 - {e}")
        print("------------------------\n")

    except Exception as e:
        logging.error(f"分析过程中发生错误: {e}")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="测试脚本，用于分析指定进程中特定地址的结构体。")
    parser.add_argument("process_name", help="要附加到的目标进程名称 (例如, 'Tutorial-x86_64.exe')")
    parser.add_argument("address", help="要分析的结构体的基地址 (十六进制, 例如 '0x6DF0E68')")
    parser.add_argument("struct_name", help="要使用的结构体定义的名称 (例如, 'Player')")
    
    args = parser.parse_args()

    try:
        # 将十六进制字符串地址转换为整数
        address_int = int(args.address, 16)
    except ValueError:
        logging.error(f"无效的地址格式: {args.address}。请输入一个有效的十六进制地址 (例如, '0x1234ABCD')。")
        sys.exit(1)

    DEFINITIONS_FILE = os.path.join(os.path.dirname(__file__), '..', 'definitions.yaml')

    logging.info(f"--- 开始执行测试 ---")
    logging.info(f"进程: {args.process_name}, 地址: {hex(address_int)}, 结构体: {args.struct_name}")
    
    try:
        analyze_address(args.process_name, address_int, args.struct_name, DEFINITIONS_FILE)
    except Exception as e:
        logging.error(f"测试失败。错误: {e}")