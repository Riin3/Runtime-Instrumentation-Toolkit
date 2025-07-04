import yaml
import pymem
import pymem.process as pm_process
from pymem import pattern
from typing import Dict, Any, Optional, List, Tuple
from unittest.mock import MagicMock
import struct
import math
import logging
from pymem import memory
from pymem.exception import MemoryReadError
from .advanced_scanner import AdvancedScanner
from .hook_manager import HookManager, DR7_BREAK_ON_WRITE, DR7_BREAK_ON_READWRITE, CONTEXT, PVECTORED_EXCEPTION_HANDLER, EXCEPTION_POINTERS
import ctypes
from ctypes import wintypes
from threading import Event
from .code_cave_hooker import CodeCaveHooker

# Windows API for listing threads
TH32CS_SNAPTHREAD = 0x00000004
INVALID_HANDLE_VALUE = -1

class THREADENTRY32(ctypes.Structure):
    _fields_ = [
        ('dwSize', wintypes.DWORD),
        ('cntUsage', wintypes.DWORD),
        ('th32ThreadID', wintypes.DWORD),
        ('th32OwnerProcessID', wintypes.DWORD),
        ('tpBasePri', wintypes.LONG),
        ('tpDeltaPri', wintypes.LONG),
        ('dwFlags', wintypes.DWORD),
    ]

kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
kernel32.Thread32First.argtypes = [wintypes.HANDLE, ctypes.POINTER(THREADENTRY32)]
kernel32.Thread32First.restype = wintypes.BOOL
kernel32.Thread32Next.argtypes = [wintypes.HANDLE, ctypes.POINTER(THREADENTRY32)]
kernel32.Thread32Next.restype = wintypes.BOOL

class StructureManager:
    """
    结构体管理器，作为框架的最高协调者。
    负责解析结构体定义，并指挥底层工具链（扫描器、注入器）
    来"挂载"和"卸载"对目标数据结构的监控。
    """

    class StructureInstance:
        """一个已挂载的结构体实例，提供成员的读写接口。"""
        def __init__(self, manager: 'StructureManager', name: str, base_ptr: int, members_def: dict):
            # 使用 object.__setattr__ 来避免触发自定义的 __setattr__
            object.__setattr__(self, '_manager', manager)
            object.__setattr__(self, '_name', name)
            object.__setattr__(self, '_base_ptr', base_ptr)
            object.__setattr__(self, '_members_def', members_def)

        def __getattr__(self, name: str) -> Any:
            if name in self._members_def:
                member_info = self._members_def[name]
                offset = member_info['offset']
                value_type = member_info['type']
                address = self._base_ptr + offset
                return self._manager.pm.read_bytes(address, 8) # 示例：读取一个指针大小
            raise AttributeError(f"'{self._name}' 实例没有名为 '{name}' 的成员。")

        def __setattr__(self, name: str, value: Any):
            if name in self._members_def:
                member_info = self._members_def[name]
                offset = member_info['offset']
                value_type = member_info['type']
                address = self._base_ptr + offset
                # 示例：写入一个指针大小
                self._manager.pm.write_bytes(address, value, 8)
            else:
                super().__setattr__(name, value)
    
    def __init__(self, pm: pymem.Pymem, scanner: AdvancedScanner, hooker: CodeCaveHooker, definitions_file: str):
        self.pm = pm
        self.scanner = scanner
        self.hooker = hooker
        self.definitions_file = definitions_file
        self.definitions = self._load_definitions()
        self.mounted_structures: Dict[str, StructureManager.StructureInstance] = {}

    def _load_definitions(self) -> dict:
        """从YAML文件中加载结构体定义。"""
        try:
            with open(self.definitions_file, 'r', encoding='utf-8') as f:
                return yaml.safe_load(f)
        except FileNotFoundError:
            logging.error(f"定义文件未找到: {self.definitions_file}")
            return {}
        except yaml.YAMLError as e:
            logging.error(f"解析定义文件失败: {e}")
            return {}

    def mount(self, structure_name: str) -> bool:
        """
        挂载一个结构体。

        这将执行AOB扫描 -> 代码注入 -> 指针捕获的完整流程。
        成功后，可以通过 get() 方法获取该结构体的可交互实例。

        :param structure_name: 在definitions.yaml中定义的结构体名称。
        :return: 挂载成功返回 True, 否则返回 False。
        """
        if structure_name in self.mounted_structures:
            logging.warning(f"结构体 '{structure_name}' 已经挂载。")
            return True

        struct_def = self.definitions.get(structure_name)
        if not struct_def or 'entry_point' not in struct_def:
            logging.error(f"在定义中未找到 '{structure_name}' 或其 'entry_point'。")
            return False

        entry_point = struct_def['entry_point']
        aob = entry_point['aob']
        instruction_length = entry_point['instruction_length']
        hook_name = f"{structure_name}_Hook"

        logging.info(f"[{structure_name}] 正在挂载... 扫描AOB: {aob}")
        scan_results = self.scanner.aob_scan(aob, scan_mode='first')
        if not scan_results:
            logging.error(f"[{structure_name}] AOB扫描失败，无法找到指令地址。")
            return False
        
        instruction_address = scan_results[0]
        logging.info(f"[{structure_name}] 扫描成功，指令地址: {hex(instruction_address)}")
        
        original_bytes = self.pm.read_bytes(instruction_address, instruction_length)

        success = self.hooker.install_hook(
            name=hook_name,
            instruction_address=instruction_address,
            instruction_length=instruction_length,
            original_bytes=original_bytes
        )

        if not success:
            logging.error(f"[{structure_name}] 安装钩子失败。")
            return False
            
        logging.info(f"[{structure_name}] 挂载成功！等待游戏触发钩子以捕获基地址。")
        # 注意：这里我们不阻塞等待指针捕获，而是假设它会在后台发生。
        # 真实使用时，get() 方法会检查指针是否已捕获。
        return True

    def unmount(self, structure_name: str) -> bool:
        """
        卸载一个已挂载的结构体，清理所有钩子和资源。

        :param structure_name: 要卸载的结构体的名称。
        :return: 卸载成功返回 True。
        """
        hook_name = f"{structure_name}_Hook"
        if hook_name not in self.hooker.installed_hooks:
            logging.warning(f"结构体 '{structure_name}' 并未挂载或已被卸载。")
            return True
        
        if structure_name in self.mounted_structures:
            del self.mounted_structures[structure_name]

        return self.hooker.uninstall_hook(hook_name)

    def get(self, structure_name: str) -> Optional[StructureInstance]:
        """
        获取一个已挂载的结构体的可交互实例。

        在后台，它会检查底层的钩子是否已经成功捕获到了基地址。

        :param structure_name: 结构体的名称。
        :return: 一个可交互的 StructureInstance 实例，如果未挂载或未捕获到指针则返回 None。
        """
        struct_def = self.definitions.get(structure_name)
        if not struct_def:
            return None

        hook_name = f"{structure_name}_Hook"
        base_ptr = self.hooker.get_captured_pointer(hook_name)

        if not base_ptr:
            logging.debug(f"尚未捕获到 '{structure_name}' 的基地址。")
            return None
            
        if structure_name not in self.mounted_structures:
             self.mounted_structures[structure_name] = self.StructureInstance(
                self, structure_name, base_ptr, struct_def.get('members', {})
            )
        
        return self.mounted_structures[structure_name]

    def unmount_all(self):
        """卸载所有已挂载的结构体。"""
        self.hooker.uninstall_all_hooks()
        self.mounted_structures.clear()
        logging.info("所有结构体均已卸载。")

    def add_definition(self, name, definition=None):
        """新增结构体定义。如果未提供 definition，则创建一个空的 members 结构。"""
        if definition is None:
            definition = {'members': {}}
        # 如果直接传入成员映射，则包装到 members 键下
        if 'members' not in definition:
            definition = {'members': definition}
        self.definitions[name] = definition

    def get_definition(self, name):
        """返回指定结构体的定义，不存在则返回 None。"""
        return self.definitions.get(name)

    def remove_definition(self, name):
        if name in self.definitions:
            del self.definitions[name]

    def update_definition(self, name, definition):
        # 同样确保保持统一的数据结构格式
        if 'members' not in definition:
            definition = {'members': definition}
        self.definitions[name] = definition

    def read_value(self, address, value_type):
        """
        从指定地址读取特定类型的值。

        :param address: 内存地址
        :param value_type: pymem支持的数据类型字符串 (e.g., 'int', 'float')
        :return: 读取到的值
        """
        # 简单的类型映射，可以根据需要扩展
        type_map = {
            'int': self.pm.read_int,
            'uint': self.pm.read_uint,
            'long': self.pm.read_long,
            'ulong': self.pm.read_ulong,
            'short': self.pm.read_short,
            'ushort': self.pm.read_ushort,
            'float': self.pm.read_float,
            'double': self.pm.read_double,
            'char': lambda addr: self.pm.read_bytes(addr, 1),
            'bool': self.pm.read_bool,
            'string': self.pm.read_string,
            # 更多类型...
        }
        read_func = type_map.get(value_type.lower())
        if not read_func:
            raise ValueError(f"不支持的类型: {value_type}")
        return read_func(address)

    def write_value(self, address, value_type, value):
        """
        将特定类型的值写入指定地址。

        :param address: 内存地址
        :param value_type: pymem支持的数据类型字符串
        :param value: 要写入的值
        """
        type_map = {
            'int': self.pm.write_int,
            'uint': self.pm.write_uint,
            'long': self.pm.write_long,
            'ulong': self.pm.write_ulong,
            'short': self.pm.write_short,
            'ushort': self.pm.write_ushort,
            'float': self.pm.write_float,
            'double': self.pm.write_double,
            'char': lambda addr, val: self.pm.write_bytes(addr, bytes(val, 'utf-8') if isinstance(val, str) else val, 1),
            'bool': self.pm.write_bool,
            'string': self.pm.write_string,
            # 更多类型...
        }
        write_func = type_map.get(value_type.lower())
        if not write_func:
            raise ValueError(f"不支持的类型: {value_type}")
        
        # 根据类型进行安全转换；string/char 不做数值转换
        try:
            vtype = value_type.lower()
            if vtype in ['float', 'double']:
                converted_value = float(value)
            elif vtype in ['bool']:
                converted_value = bool(value)
            elif vtype in ['string']:
                converted_value = str(value)
            elif vtype in ['char']:
                # 对于单字符，接受 str 或 int 或 bytes
                if isinstance(value, (bytes, bytearray)):
                    converted_value = value
                elif isinstance(value, int):
                    converted_value = bytes([value])
                else:
                    converted_value = bytes(value[0], 'utf-8')
            else:
                converted_value = int(value)
        except (ValueError, TypeError, IndexError):
            raise TypeError(f"无法将值 '{value}' 转换为类型 '{value_type}'")

        return write_func(address, converted_value)

    def save_definitions(self, file_path: Optional[str] = None):
        """将当前 definitions 保存回 YAML 文件。默认使用初始化时的 definitions_file。"""
        target_path = file_path or self.definitions_file
        if not target_path:
            raise ValueError("save_definitions 需要提供文件路径，且初始化时未指定 definitions_file。")
        with open(target_path, 'w', encoding='utf-8') as f:
            yaml.safe_dump(self.definitions, f, allow_unicode=True, sort_keys=False)
        logging.info(f"已保存 {len(self.definitions)} 个结构体定义到 {target_path}。")

    def build_from_aob(self, structure_name: str) -> Optional['StructureInstance']:
        """
        通过新的混合模式（特征+偏移）定位并构建结构体实例。
        """
        struct_def = self.get_definition(structure_name)
        if not struct_def:
            logging.error(f"未找到名为 '{structure_name}' 的结构体定义。")
            return None

        member_addresses = self._resolve_structure(structure_name)
        if not member_addresses:
            logging.error(f"构建失败：无法解析 '{structure_name}' 的任何成员地址。")
                return None
            
        addrs_str = {k: hex(v) for k, v in member_addresses.items()}
        logging.info(f"成功解析到 '{structure_name}' 的成员地址: {addrs_str}")
        
        # 确定基地址：优先使用 offset 为 0 的成员地址，否则使用第一个找到的地址
        base_address = 0
        if member_addresses:
            members_def = struct_def.get('members', {})
            base_member_name = next((name for name, deets in members_def.items() if deets.get('offset') == 0), None)
            if base_member_name and base_member_name in member_addresses:
                base_address = member_addresses[base_member_name]
            else:
                # Fallback to the first available address if no zero-offset member is found
                base_address = next(iter(member_addresses.values()))

        return self.StructureInstance(self, structure_name, base_address, struct_def.get('members', {}))

    # ------------------------------------------------------------------
    # 自动探测内存区域字段类型（实验性功能）
    # ------------------------------------------------------------------

    def auto_probe(self, base_address: int, size: int, step: int = 4):
        """
        在给定地址范围内按步长扫描内存，对每个偏移尝试推断数据类型。

        返回格式示例:
        [
            {"offset": 0x0,  "type": "int",    "raw": 123},
            {"offset": 0x4,  "type": "float",  "raw": 12.5},
            {"offset": 0x18, "type": "string", "raw": "Player1"},
        ]
        """
        probed_data = {}
        for offset in range(0, size, step):
            addr = base_address + offset
            guessed_type = self._guess_type(addr)
            if guessed_type:
                value = self.read_value(addr, guessed_type)
                probed_data[f"offset_{offset:04x}"] = {'type': guessed_type, 'value': value}
        return probed_data

    def _guess_type(self, addr: int, pointer_size: int = 8):
        """
        根据地址处的数据猜测其可能的类型（简化版）。
        """
        try:
            # 尝试作为指针读取，并验证指针指向的地址是否可读
            ptr = self.pm.read_longlong(addr) if pointer_size == 8 else self.pm.read_int(addr)
            ptr_int = int(ptr)
            if ptr_int > 0x10000: # 排除一些明显不是地址的值
                self.pm.read_bytes(ptr_int, 1) # 尝试读取一个字节，如果失败会抛出异常
                return 'pointer'
        except Exception:
            pass

        try:
            # 尝试作为可打印字符串
            val = self.pm.read_bytes(addr, 4)
            if val and all(32 <= b <= 126 for b in val):
                return 'string' # 可能是一个字符串
        except Exception:
            pass
        return None

    def _resolve_structure(self, struct_name: str) -> Optional[Dict[str, int]]:
        struct_def = self.get_definition(struct_name)
        if not struct_def or 'finders' not in struct_def:
            logging.warning(f"'{struct_name}' 没有找到有效的 finders 定义。")
            return None

        finders = struct_def['finders']
        
        # 1. 快速通道 (该逻辑已废弃，将来可基于新API重构)
        # ...

        # 2. 交叉验证通道 (主要逻辑)
        logging.info(f"[{struct_name}] 尝试交叉验证通道...")
        validated_results = self._full_scan_resolve(finders)
        if validated_results:
            logging.info(f"[{struct_name}] 交叉验证成功！")
            self._self_heal_offsets_and_save(struct_name, validated_results)
            return {finder['member']: addr for finder, addr in validated_results}

        logging.warning(f"[{struct_name}] 交叉验证失败。")
        
        # 3. 发现与自愈通道
        if struct_def.get('self_healing', False):
            logging.info(f"[{struct_name}] 尝试发现与自愈通道...")
            discovered_results = self._discovery_scan(finders)
            if len(discovered_results) > 1:
                logging.info(f"[{struct_name}] 发现通道找到了多个成员，触发强制自愈。")
                made_changes = self._self_heal_offsets_and_save(struct_name, discovered_results)
                if made_changes:
                    logging.warning(
                        f"[{struct_name}] 偏移量已更新并保存。请重新运行扫描以使用新的偏移量。"
                    )
                else:
                    logging.info(f"[{struct_name}] 偏移量已是最新，问题可能出在AOB本身。")
            elif discovered_results:
                logging.info(f"[{struct_name}] 发现通道只找到了一个成员，无法自愈。")
        
        logging.error(f"[{struct_name}] 所有通道都已失败，无法解析地址。")
                return None
        
    def _full_scan_resolve(self, finders: list) -> List[Tuple[dict, int]]:
        scan_results = {}
        for finder in finders:
            matches = self.scanner.aob_scan(finder['aob'], scan_mode='all')
            if matches:
                scan_results[finder['name']] = {'finder_def': finder, 'addresses': matches}

        if len(scan_results) < 2:
                return []

        base_finder_name = min(scan_results, key=lambda k: len(scan_results[k]['addresses']))
        base_candidates = scan_results[base_finder_name]
        other_finders = {k: v for k, v in scan_results.items() if k != base_finder_name}

        for base_addr in base_candidates['addresses']:
            validated_addresses = {base_finder_name: base_addr}
            all_others_matched = True

            for other_name, other_candidates in other_finders.items():
                offset = base_candidates['finder_def'].get('relative_offsets', {}).get(other_name)
                
                if offset is None:
                    reverse_offset = other_candidates['finder_def'].get('relative_offsets', {}).get(base_finder_name)
                    if reverse_offset is not None:
                        predicted_addr = base_addr - reverse_offset
                    else:
                        all_others_matched = False
                        break
                else:
                    predicted_addr = base_addr + offset

                if predicted_addr in other_candidates['addresses']:
                    validated_addresses[other_name] = predicted_addr
                else:
                    all_others_matched = False
                    break
            
            if all_others_matched:
                final_results = [
                    (scan_results[name]['finder_def'], addr) for name, addr in validated_addresses.items()
                ]
                return final_results
        
        return []
        
    def _self_heal_offsets_and_save(self, struct_name: str, found_finders_with_addr: list[tuple[dict, int]]) -> bool:
        if len(found_finders_with_addr) < 2:
            return False
        
        struct_def = self.definitions[struct_name]
        finders_list_in_def = struct_def['finders']
        finder_map_by_name = {f['name']: f for f in finders_list_in_def}
        made_changes = False

        for i in range(len(found_finders_with_addr)):
            for j in range(len(found_finders_with_addr)):
                if i == j: continue
                finder_a_def, addr_a = found_finders_with_addr[i]
                finder_b_def, addr_b = found_finders_with_addr[j]
                
                name_a, name_b = finder_a_def['name'], finder_b_def['name']
                new_offset = addr_b - addr_a
                
                target_finder = finder_map_by_name.get(name_a)
                if target_finder:
                    if 'relative_offsets' not in target_finder:
                        target_finder['relative_offsets'] = {}
                    old_offset = target_finder['relative_offsets'].get(name_b)
                    if old_offset != new_offset:
                        target_finder['relative_offsets'][name_b] = new_offset
                    made_changes = True

        if made_changes:
            self.save_definitions()
        return made_changes

    def _validate_aob_at_address(self, address: int, aob_string: str) -> bool:
        """验证指定地址的内存是否与AOB模式匹配。"""
        # 这个函数现在可以直接调用新的扫描器来完成，更简单
        matches = self.scanner.aob_scan(aob_string, scan_mode='full') # 这里可能需要一个更精确的scan_at_address
        return address in matches

    def _discovery_scan(self, finders: list) -> List[Tuple[dict, int]]:
        discovered_results = []
        for finder in finders:
            matches = self.scanner.aob_scan(finder['aob'], scan_mode='all')
            if matches:
                discovered_results.append((finder, matches[0]))
        return discovered_results

    def build_from_hook(self, name: str) -> Optional[int]:
        """
        通过硬件断点和钩子全自动寻找结构体基址。
        这是推荐的、最现代的方法。
        """
        definition = self._get_definition(name)
        if not definition:
            logging.error(f"未找到 '{name}' 的定义。")
            return None

        logging.info(f"开始通过 Hook 构建结构体: {name}")

        # 1. 使用 bootstrap_finder 找到一个引导地址
        bootstrap_finder_def = definition.get('bootstrap_finder')
        if not bootstrap_finder_def:
            logging.error(f"定义 {name} 中缺少 'bootstrap_finder' 用于引导。")
            return None
        
        finder_type = bootstrap_finder_def.get('type', 'aob') # 默认为aob
        bootstrap_address = 0

        logging.info(f"使用 {bootstrap_finder_def.get('name')} (类型: {finder_type}) 进行引导...")

        if finder_type == 'aob':
            aob = bootstrap_finder_def.get('aob')
            scan_mode = bootstrap_finder_def.get('scan_mode', 'priority')
            module = bootstrap_finder_def.get('module')
            if not aob:
                logging.error(f"引导扫描器 {bootstrap_finder_def.get('name')} 缺少 'aob'。")
                return None
            
            scan_results = []
            if scan_mode == 'module':
                scan_results = self.scanner.aob_scan(pattern=aob, scan_mode='module', module_name=module)
            else:
                scan_results = self.scanner.aob_scan(pattern=aob, scan_mode=scan_mode)
            
            if not scan_results:
                logging.error("AOB引导扫描失败，无法找到初始地址。")
                return None
            bootstrap_address = scan_results[0]
        
        elif finder_type == 'pointer_path':
            address = self._resolve_pointer_path(bootstrap_finder_def)
            if not address:
                logging.error("指针路径解析失败，无法找到初始地址。")
                return None
            bootstrap_address = address
        
        else:
            logging.error(f"不支持的引导扫描器类型: {finder_type}")
            return None

        logging.info(f"引导成功，在 {hex(bootstrap_address)} 找到初始地址。")

        # 2. 设置硬件断点并等待捕获
        capture_event = Event()
        captured_data = {}

        def _hook_callback(context):
            logging.info("硬件断点回调触发！")
            captured_data['rip'] = context.Rip
            captured_data['rcx'] = context.Rcx
            capture_event.set()

        with HookManager(self.pm) as hooker:
            success = hooker.set_hardware_breakpoint(
                address=bootstrap_address,
                break_on=DR7_BREAK_ON_READWRITE,
                callback=_hook_callback
            )
            if not success:
                logging.error("设置硬件断点失败。")
                return None

            logging.info(f"已在地址 {hex(bootstrap_address)} 设置硬件断点。请在游戏中执行相应操作...")
            
            triggered = capture_event.wait(timeout=30)

            if not triggered:
                logging.error("等待捕获超时。无法自动定位结构体。")
                # 即使超时，也要确保断点被移除
                hooker.remove_hardware_breakpoint(bootstrap_address)
                return None

        # 断点命中后，HookManager的__exit__会自动清理，我们也可以手动清理
        # 但我们的一次性断点逻辑使得它在触发后就自行移除了

        rip = captured_data.get('rip')
        rcx = captured_data.get('rcx')
        
        if not rip or not rcx:
            logging.error("捕获到的数据不完整。")
            return None

        logging.info(f"成功捕获！函数地址: {hex(rip)}, 结构体基地址: {hex(rcx)}")
        
        # TODO: 将 rip 和 rcx 保存到配置文件中
        return rcx

    def build_from_base_address(self, structure_name: str, base_address: int) -> Optional['StructureInstance']:
        """
        根据已知的基地址，构建一个结构体实例。
        这是在通过hook等方式获得基地址后，创建实例的标准方法。
        """
        struct_def = self.get_definition(structure_name)
        if not struct_def:
            logging.error(f"构建实例失败：未找到 '{structure_name}' 的定义。")
            return None
        
        members_def = struct_def.get('members', {})
        
        # 我们需要为 StructureInstance 提供一个 member_addresses 字典。
        # 即使只提供一个 '锚点' 地址（即 offset 为 0 的成员地址），
        # StructureInstance 也能从中计算出其他所有成员的地址。
        base_member_name = next((name for name, deets in members_def.items() if deets.get('offset') == 0), None)
        
        member_addresses = {}
        if base_member_name:
            # RCX/this 指针就是 offset 为 0 的成员的地址
            member_addresses[base_member_name] = base_address
        else:
            logging.warning(f"结构体 '{structure_name}' 定义中缺少 offset 为 0 的成员，无法创建实例。")
            return None # 或者我们可以将 base_address 直接作为实例的基地址

        return self.StructureInstance(
            self, 
            structure_name, 
            base_address, 
            members_def
        )

    def _resolve_pointer_path(self, finder_def: dict) -> Optional[int]:
        """解析一个指针路径，返回最终指向的地址。"""
        module_name = finder_def.get('module')
        base_offset = finder_def.get('base_offset')
        offsets = finder_def.get('offsets', [])

        if not module_name or base_offset is None:
            logging.error("指针路径定义不完整，缺少'module'或'base_offset'。")
            return None

        module = self.scanner.get_module_by_name(module_name)
        if not module:
            logging.error(f"未找到指针路径所需的模块: {module_name}")
            return None
        
        is_64bit = self.scanner.is_64bit
        read_ptr = self.pm.read_longlong if is_64bit else self.pm.read_int
        
        try:
            # 从模块基地址开始
            address = module.lpBaseOfDll
            
            # 加上基础偏移
            address += base_offset
            
            # 遍历并解引用所有后续偏移
            for offset in offsets:
                address = read_ptr(address)
                address += offset
                
        except MemoryReadError as e:
            logging.error(f"解析指针路径时发生内存读取错误: {e}")
            return None
        
        return address

    def _get_definition(self, name: str) -> Optional[Dict[str, Any]]:
        return self.definitions.get(name)

    def _get_finder(self, name: str) -> Optional[Dict[str, Any]]:
        # 遍历所有定义，查找包含 'finders' 的定义
        for definition_name, definition_content in self.definitions.items():
            if 'finders' in definition_content:
                # 在 finders 列表中查找匹配的 finder
                for finder in definition_content['finders']:
                    if finder.get('name') == name:
                        return finder
        return None