#!/usr/bin/env python3
"""CLI 工具：根据基址扫描并半自动生成结构体定义。

用法示例:
    python scripts/struct_generator.py Tutorial-x86_64.exe 0x140000000 --size 256 --name PlayerAuto
"""

import argparse
import os
import sys
import yaml
from pymem import Pymem

# 将项目根目录加入路径，以便导入 core 模块
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR)
if PROJECT_ROOT not in sys.path:
    sys.path.append(PROJECT_ROOT)

from core.structure_manager import StructureManager

DEFAULT_DEFINITIONS_PATH = os.path.join(PROJECT_ROOT, 'definitions.yaml')


def main():
    parser = argparse.ArgumentParser(description="扫描内存并生成结构体定义")
    parser.add_argument('process', help='目标进程名称，例如 Game.exe')
    parser.add_argument('base', help='基地址，十六进制，例如 0x140000000')
    parser.add_argument('--size', type=int, default=256, help='扫描长度（字节）')
    parser.add_argument('--step', type=int, default=4, help='步进字节数')
    parser.add_argument('--name', required=True, help='生成的结构体名称')
    parser.add_argument('--output', choices=['yaml', 'file'], default='yaml', help='输出方式: yaml 打印到终端, file 写入 definitions.yaml')
    args = parser.parse_args()

    try:
        base_addr = int(args.base, 16)
    except ValueError:
        print('基地址格式错误，应为十六进制，如 0x12345678', file=sys.stderr)
        sys.exit(1)

    print(f"附加到进程 {args.process}…")
    pm = Pymem(args.process)
    manager = StructureManager(pm)

    print(f"开始探测 {hex(base_addr)} ~ {hex(base_addr + args.size)} …")
    probes = manager.auto_probe(base_addr, args.size, args.step)

    if not probes:
        print('未能在指定范围内推断出任何字段。')
        sys.exit(0)

    # 组装 members
    members = {}
    for item in probes:
        field_name = f"field_0x{item['offset']:X}"
        members[field_name] = {
            'type': item['type'],
            'offset': item['offset']
        }

    struct_def = {args.name: {'members': members}}

    if args.output == 'yaml':
        print('\n--- 生成 YAML ---')
        print(yaml.safe_dump(struct_def, allow_unicode=True, sort_keys=False))
    else:
        # 写入文件
        print(f"写入 definitions.yaml ({DEFAULT_DEFINITIONS_PATH}) …")
        if os.path.exists(DEFAULT_DEFINITIONS_PATH):
            with open(DEFAULT_DEFINITIONS_PATH, 'r', encoding='utf-8') as f:
                existing = yaml.safe_load(f) or {}
        else:
            existing = {}
        existing.update(struct_def)
        with open(DEFAULT_DEFINITIONS_PATH, 'w', encoding='utf-8') as f:
            yaml.safe_dump(existing, f, allow_unicode=True, sort_keys=False)
        print('写入完成。')


if __name__ == '__main__':
    main() 