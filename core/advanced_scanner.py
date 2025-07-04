import pymem
import pymem.process
from pymem import pattern as pattern_util
from typing import List, Any, Optional, Tuple, Union, Dict
import subprocess
import time
import capstone
import yaml
import os
from pymem.exception import ProcessNotFound, MemoryReadError
import logging
import re

# 计划引入的库，暂时注释
# import keystone

def aob_scan_in_memory(
    pattern_str: str, 
    memory_dump: bytes, 
    alignment: int = 4
) -> List[int]:
    """
    在一个内存转储(bytes)中搜索AOB模式。
    这是在Python级别实现的、支持通配符的真正AOB扫描。

    :param pattern_str: AOB模式字符串，例如 "48 8D 0D ?? ?? ?? ?? E8"。
    :param memory_dump: 内存区域的字节转储。
    :param alignment: 扫描对齐，对于大多数x86指令，4字节对齐可以显著提速。
    :return: 内存转储中所有匹配项的偏移量列表。
    """
    pattern_parts = pattern_str.split()
    pattern_bytes = []
    mask = []

    for part in pattern_parts:
        if part == '??' or part == '?':
            pattern_bytes.append(0)  # 字节可以是任何值
            mask.append(False)       # 但我们在比较时会忽略它
        else:
            try:
                pattern_bytes.append(int(part, 16))
                mask.append(True)
            except ValueError:
                logging.error(f"无效的AOB模式部分: {part}")
                return []
    
    found_offsets = []
    pattern_len = len(pattern_bytes)
    dump_len = len(memory_dump)

    for i in range(0, dump_len - pattern_len + 1, alignment):
        match = True
        for j in range(pattern_len):
            if mask[j] and memory_dump[i + j] != pattern_bytes[j]:
                match = False
                break
        if match:
            found_offsets.append(i)
            
    return found_offsets

class AdvancedScanner:
    """
    一个现代化的内存扫描器，集成了AOB扫描、指令解析和结构化数据读取功能。
    """
    def __init__(self, pm: pymem.Pymem, process_name: Optional[str] = None):
        """
        初始化扫描器。

        :param pm: 一个已经附加到目标进程的 pymem.Pymem 对象。
        :param process_name: 目标进程的名称。
        """
        if not pm or not pm.process_handle:
            raise ValueError("提供给 AdvancedScanner 的 Pymem 对象无效或未附加到进程。")
        self.pm = pm
        self.pid = pm.process_id
        # 若未显式提供进程名，则尝试从 pymem 对象获取
        self.process_name = process_name or getattr(pm, 'process_name', 'Unknown')
        self.is_64bit = pymem.process.is_64_bit(self.pm.process_handle)
        # 存储模块时，将模块名统一转为小写，以实现不区分大小写的查找
        self.modules = {module.name.lower(): module for module in self.pm.list_modules()}

        # 初始化反汇编/汇编引擎 (待完成)
        self.cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64 if self.is_64bit else capstone.CS_MODE_32)
        # self.ks = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_64 if self.is_64bit else keystone.KS_MODE_32)

        logging.info(f"成功附加到进程: {self.process_name} ({'64-bit' if self.is_64bit else '32-bit'})")
        
        self.priority_modules: List[Any] = []
        self.engine_profiles: Dict[str, Any] = self._load_engine_profiles()
        self.priority_modules = self._load_and_identify_priority_modules()

    def _load_engine_profiles(self) -> Dict[str, Any]:
        """从YAML文件加载游戏引擎配置。"""
        profiles_path = os.path.join(os.path.dirname(__file__), '..', 'engine_profiles.yaml')
        if not os.path.exists(profiles_path):
            logging.warning(f"引擎配置文件不存在: {profiles_path}")
            return {}
        try:
            with open(profiles_path, 'r', encoding='utf-8') as f:
                return yaml.safe_load(f)
        except Exception as e:
            logging.error(f"加载引擎配置文件失败: {e}")
            return {}

    def _load_and_identify_priority_modules(self) -> List[Any]:
        """加载引擎配置，并返回当前进程中存在的优先模块列表。"""
        profiles_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'engine_profiles.yaml')
        if not os.path.exists(profiles_path):
            return []
        
        with open(profiles_path, 'r', encoding='utf-8') as f:
            profiles = yaml.safe_load(f)
        
        if not profiles or 'priority_modules' not in profiles:
            return []
            
        known_priority_names = [name.lower() for name in profiles['priority_modules']]
        
        # 找出当前进程加载的模块与已知优先模块的交集
        loaded_priority_modules = []
        for known_name in known_priority_names:
            if known_name in self.modules:
                loaded_priority_modules.append(self.modules[known_name])
                
        return loaded_priority_modules

    def get_module_by_name(self, module_name: str):
        """
        通过模块名获取模块对象（不区分大小写）。
        """
        return self.modules.get(module_name.lower())

    def generate_pattern(self, address: int, size: int = 128, min_length: int = 16) -> Optional[Tuple[bytes, str]]:
        """
        为一个地址生成一个唯一的AOB模式。采用高效的逐步扩展策略，以最大限度地减少全内存扫描的次数。

        :param address: 要为其生成模式的目标地址。
        :param size: 从地址周围读取的内存大小。这块内存是生成和验证模式的"靶场"。
        :param min_length: 生成的模式的最小长度。
        :return: (原始字节, AOB字符串) 或 None。
        """
        try:
            original_bytes = self.pm.read_bytes(address, size)
            
            # 从中间向两边扩展，寻找唯一的模式
            for length in range(min_length, size // 2, 2):
                start = (size - length) // 2
                end = start + length
                sub_pattern_bytes = original_bytes[start:end]

                # 将字节转换为AOB字符串，例如 "48 89 5C 24 ??"
                aob_string = ' '.join([f'{b:02X}' for b in sub_pattern_bytes])

                # 在完整的原始字节块中扫描，以验证唯一性
                all_matches_in_block = [m.start() for m in re.finditer(re.escape(sub_pattern_bytes), original_bytes)]
                
                if len(all_matches_in_block) == 1:
                    logging.info(f"成功为地址 {hex(address)} 生成唯一AOB模式 (长度 {length})")
                    return sub_pattern_bytes, aob_string

            # 如果在初始size内找不到唯一模式，尝试在更大的内存区域中验证
            logging.warning(f"在 {size} 字节范围内无法生成唯一模式，尝试扩大扫描范围验证...")
            
            # 使用最后一次的、最长的模式进行全模块扫描
            final_aob_string = ' '.join([f'{b:02X}' for b in original_bytes])
            all_matches = self.aob_scan(final_aob_string, scan_mode='all')
            
            if len(all_matches) == 1 and all_matches[0] == address:
                logging.info(f"扩大范围扫描后，确认地址 {hex(address)} 的模式是唯一的。")
                return original_bytes, final_aob_string
            
            elif len(all_matches) > 1:
                logging.info(f"找到 {len(all_matches)} 个匹配项，无法生成唯一模式。")
            
            elif not all_matches:
                logging.error(f"模式未找到任何匹配，甚至不包括原始地址。内存可能已改变。")

        except Exception as e:
            logging.error(f"AOB模式生成期间发生错误: {e}", exc_info=True)

        logging.error(f"无法为地址 {hex(address)} 生成唯一的AOB模式。")
        return None

    def aob_scan(
        self,
        pattern: str,
        scan_mode: str = 'priority',
        module_name: Optional[str] = None
    ) -> List[int]:
        """
        在目标进程中执行AOB扫描。这个版本使用了在Python中实现的、
        可靠的、支持通配符的扫描逻辑。

        :param pattern: AOB模式字符串。
        :param scan_mode: 扫描模式: 'priority', 'module', 'all', 'full'。
        :param module_name: 当 scan_mode 为 'module' 时需要。
        :return: 找到的所有匹配地址的列表。
        """
        if scan_mode == 'module' and module_name:
            module = self.get_module_by_name(module_name)
            if not module:
                logging.warning(f"扫描失败，未找到模块: {module_name}")
                return []
            return self._scan_in_module(pattern, module)

        if scan_mode == 'priority' and self.priority_modules:
            logging.info("执行优先模块扫描...")
            all_matches = []
            for module in self.priority_modules:
                matches = self._scan_in_module(pattern, module)
                all_matches.extend(matches)
            if all_matches:
                return all_matches

        if scan_mode in ['priority', 'all']:
            logging.warning("优先/全模块扫描无果或未执行，扫描所有已加载模块...")
            all_matches = []
            for module in self.modules.values():
                matches = self._scan_in_module(pattern, module)
                all_matches.extend(matches)
            if all_matches:
                return all_matches

        logging.warning("所有模块扫描均无果，执行最终的全内存扫描 (这可能会非常慢)...")
        # pymem 的 iter_memory_regions 似乎不太稳定，我们暂时不实现 'full' 模式
        # all_matches = self._scan_full_memory(pattern)
        return []

    def _scan_in_module(self, pattern: str, module: Any) -> List[int]:
        """在指定模块中执行AOB扫描"""
        try:
            logging.debug(f"正在读取模块 {module.name} ({module.SizeOfImage} 字节)...")
            module_bytes = self.pm.read_bytes(module.lpBaseOfDll, module.SizeOfImage)
        except Exception as e:
            logging.error(f"读取模块 {module.name} 内存失败: {e}")
            return []

        found_offsets = aob_scan_in_memory(pattern, module_bytes)
        
        if found_offsets:
            absolute_addresses = [module.lpBaseOfDll + offset for offset in found_offsets]
            logging.info(f"在模块 {module.name} 中找到 {len(absolute_addresses)} 个匹配项。")
            return absolute_addresses
        return []

    def resolve_rip_relative_address(self, address: int, instruction_offset: Optional[int] = None, instruction_size: Optional[int] = None) -> int:
        """
        解析一条基于RIP寄存器的相对寻址指令，计算出其引用的绝对地址。
        这个新版本使用capstone来确保准确性，而不是手动计算。

        :param address: 包含相对寻址指令的地址。
        :param instruction_offset: (已弃用) 为了兼容性保留。
        :param instruction_size: (已弃用) 为了兼容性保留。
        :return: 解析出的绝对地址。
        """
        try:
            # 读取指令字节码，通常15个字节足够覆盖最长的x86指令
            instruction_bytes = self.pm.read_bytes(address, 15)
            
            # 使用capstone反汇编
            disassembled = list(self.cs.disasm(instruction_bytes, address, count=1))
            
            if not disassembled:
                logging.error(f"Capstone无法在地址 {hex(address)} 进行反汇编。")
                return 0

            insn = disassembled[0]
            
            # 检查是否是 LEA 指令且操作数是 rip 相对寻址
            # Capstone 会为我们直接计算好目标地址
            if insn.mnemonic == 'lea' and 'rip' in insn.op_str:
                # 第二个操作数是内存地址
                # op_str 类似于 "rax, [rip + 0x12345]"
                # 我们需要从中解析出地址
                # capstone的x86_op有一个mem属性，其中包含disp(位移)和base(基址)
                # 但更简单的方法是直接利用它的字符串输出
                if len(insn.operands) > 1 and insn.operands[1].type == capstone.x86.X86_OP_MEM:
                    mem = insn.operands[1].mem
                    if mem.base == capstone.x86.X86_REG_RIP:
                        # 绝对地址 = 下一条指令的地址 + 位移
                        absolute_address = insn.address + insn.size + mem.disp
                        logging.info(f"Capstone解析: {insn.mnemonic} {insn.op_str} -> 绝对地址: {hex(absolute_address)}")
                        return absolute_address

                logging.error(f"指令 {insn.mnemonic} {insn.op_str} 不是预期的RIP相对寻址LEA指令。")
                return 0
            
            # 如果不是LEA，或者不包含RIP，也需要返回
            logging.warning(f"指令 {insn.mnemonic} {insn.op_str} 在 {hex(address)}，不是或无法解析为RIP相对寻址。")
            return 0
            
        except Exception as e:
            logging.error(f"使用Capstone解析RIP相对地址时发生错误: {e}", exc_info=True)
            return 0

    def allocate_memory(self, size: int, protect: int = 0x40) -> int:
        """
        在目标进程中分配内存。

        :param size: 要分配的内存大小（字节）。
        :param protect: 内存保护标志, 默认为 PAGE_EXECUTE_READWRITE (0x40).
        :return: 分配的内存区域的基址，失败则返回 0。
        """
        try:
            # pymem.memory.PAGE_EXECUTE_READWRITE = 0x40
            address = self.pm.allocate(size)
            if not address:
                raise MemoryError("无法在目标进程中分配内存")
            logging.info(f"成功分配 {size} 字节内存于地址: {hex(address)}")
            return address
        except Exception as e:
            logging.error(f"分配内存失败: {e}")
            return 0

    def write_memory(self, address: int, data: bytes) -> bool:
        """
        向目标进程的指定地址写入字节数据。

        :param address: 目标地址。
        :param data: 要写入的字节数据。
        :return: 成功返回 True, 失败返回 False。
        """
        try:
            self.pm.write_bytes(address, data, len(data))
            return True
        except Exception as e:
            logging.error(f"写入内存失败: {e}")
            return False

    def create_remote_thread(self, address: int) -> int:
        """
        在目标进程中创建一个新线程来执行代码。

        :param address: 要执行的代码的起始地址。
        :return: 线程句柄，失败则返回 0。
        """
        try:
            thread_handle = self.pm.start_thread(address)
            if not thread_handle:
                raise ConnectionError("无法在目标进程中创建线程")
            logging.info(f"成功创建线程，句柄: {thread_handle}")
            return thread_handle
        except Exception as e:
            logging.error(f"创建远程线程失败: {e}")
            return 0

    def inject_and_execute(self, shellcode: bytes) -> bool:
        """
        将 shellcode 注入到目标进程并执行。

        :param shellcode: 要注入和执行的机器码。
        :return: 成功返回 True，失败返回 False。
        """
        # 1. 分配内存
        mem_address = self.allocate_memory(len(shellcode))
        if not mem_address:
            return False

        # 2. 写入 shellcode
        if not self.write_memory(mem_address, shellcode):
            return False

        # 3. 创建远程线程执行
        thread_handle = self.create_remote_thread(mem_address)
        if not thread_handle:
            # 注意：这里可以添加内存释放的逻辑
            return False

        # (可选) 等待线程结束并清理
        # pymem.process.wait_for_single_object(self.pm.process_handle, thread_handle, -1)
        # self.pm.free(mem_address)

        return True

    def read_bytes(self, address: int, size: int) -> bytes:
        """读取指定地址的字节数据，增加异常处理。"""
        try:
            return self.pm.read_bytes(address, size)
        except MemoryReadError:
            logging.error(f"读取内存失败: 地址 {hex(address)} 可能无效。")
            return b''

    def disasm_block(self, address: int, size: int = 32):
        """反汇编一块内存区域并打印"""
        print(f"--- Disassembly at {hex(address)} ---")
        try:
            code = self.read_bytes(address, size)
            if not code:
                print("无法读取内存进行反汇编。")
                return
            for i in self.cs.disasm(code, address):
                print("0x%x:\t%s\t%s" % (i.address, i.mnemonic, i.op_str))
        except Exception as e:
            logging.error(f"反汇编失败: {e}")
        print("------------------------------------")

if __name__ == '__main__':
    # 用于测试的示例代码
    # 启动一个记事本进程用于测试
    print("正在启动记事本...")
    proc = subprocess.Popen(["notepad.exe"])
    time.sleep(2)  # 等待记事本完全加载

    try:
        pm = pymem.Pymem("notepad.exe")
        scanner = AdvancedScanner(pm)
        
        # 示例: 获取主模块基址
        main_module = scanner.get_module_by_name("notepad.exe")
        if main_module:
            print(f"notepad.exe 的基址是: {hex(main_module.lpBaseOfDll)}")

        # 示例: 调用AOB扫描 (全内存扫描)
        # 使用一个不太可能存在的特征码来测试函数是否能正常处理找不到结果的情况
        pattern = "AA BB CC DD EE FF 00 11 22 33"
        print(f"\n在整个进程空间中搜索一个随机AOB: {pattern}")
        found_addresses = scanner.aob_scan(pattern, scan_mode='all')

        if not found_addresses:
            print("测试通过：未找到随机特征码，函数按预期返回空列表。")
        else:
            print(f"测试失败：找到了不应存在的特征码于地址 {found_addresses}")

    except ProcessNotFound:
        print("错误：找不到记事本进程。请手动运行一个记事本。")
    except Exception as e:
        print(f"测试脚本发生未知错误: {e}")
        import traceback
        traceback.print_exc()
    finally:
        # 清理记事本进程
        if 'proc' in locals() and proc.poll() is None:
            proc.terminate()
            print("已关闭测试用的记事本进程。")