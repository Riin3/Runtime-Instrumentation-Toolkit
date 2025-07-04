import pymem
import pymem.process
import logging
from typing import Optional, Dict

# 导入 Keystone
try:
    import keystone
except ImportError:
    logging.error("Keystone-engine 未安装。请运行 'pip install keystone-engine'")
    raise

from .advanced_scanner import AdvancedScanner


class CodeCaveHooker:
    """
    一个高级的钩子工具，它能在一个指定的代码地址注入我们自己的代码（Shellcode），
    并稳定地捕获对象指针。
    """

    def __init__(self, pm: pymem.Pymem):
        """
        初始化 Code Cave Hooker。

        :param pm: 一个有效的 Pymem 实例。
        """
        self.pm = pm
        self.is_64bit = pymem.process.is_64_bit(self.pm.process_handle)

        # 初始化汇编引擎
        ks_arch = keystone.KS_ARCH_X86
        ks_mode = keystone.KS_MODE_64 if self.is_64bit else keystone.KS_MODE_32
        self.ks = keystone.Ks(ks_arch, ks_mode)

        # 用于存储钩子信息的字典
        self.installed_hooks: Dict[str, dict] = {}

    def install_hook(
        self,
        name: str,
        instruction_address: int,
        instruction_length: int,
        original_bytes: bytes
    ) -> bool:
        """
        在一个指定的指令地址安装Code Cave钩子。

        :param name: 为这个钩子起一个名字，用于管理。
        :param instruction_address: 要挂钩的指令的地址。
        :param instruction_length: 原始指令的字节长度。
        :param original_bytes: 原始指令的字节码。
        :return: 安装成功返回 True, 否则返回 False。
        """
        if name in self.installed_hooks:
            logging.warning(f"名为 '{name}' 的钩子已存在，请先卸载。")
            return False

        JMP_LEN = 5
        if instruction_length < JMP_LEN:
            logging.error(
                f"指令太短 ({instruction_length} 字节)，无法安全地放置 JMP 钩子。"
                f"需要至少 {JMP_LEN} 字节。"
            )
            return False

        # === 阶段 1: 分配内存 ===
        logging.info(f"[{name}] 阶段 1/4: 正在为Code Cave和指针存储分配内存...")
        POINTER_SIZE = 8 if self.is_64bit else 4
        try:
            pointer_storage_address = self.pm.allocate(POINTER_SIZE)
            code_cave_address = self.pm.allocate(128)
        except Exception as e:
            logging.error(f"[{name}] 内存分配失败: {e}")
            return False
        
        logging.info(f"[{name}] 内存分配成功: 指针存储于 {hex(pointer_storage_address)}, Code Cave于 {hex(code_cave_address)}")

        # === 阶段 2: 生成 Shellcode ===
        logging.info(f"[{name}] 阶段 2/4: 正在生成 Shellcode...")
        
        return_address = instruction_address + instruction_length

        shellcode_asm = f"""
            pushfq
            push rax
            mov rax, {pointer_storage_address}
            mov [rax], rcx
            pop rax
            popfq
        """
        try:
            asm_code_list, _ = self.ks.asm(shellcode_asm, addr=code_cave_address)
            jmp_code_list, _ = self.ks.asm(f"jmp {return_address}", addr=code_cave_address + 50)

            if asm_code_list is None or jmp_code_list is None:
                raise keystone.KsError("Keystone assembler returned None.")

            # 将原始指令字节附加到shellcode后面
            shellcode_bytes = b"".join([
                bytes(asm_code_list),
                original_bytes,
                bytes(jmp_code_list)
            ])
        except keystone.KsError as e:
            logging.error(f"Shellcode 汇编失败: {e}")
            self.pm.free(pointer_storage_address)
            self.pm.free(code_cave_address)
            return False


        # === 阶段 3: 注入Shellcode并放置JMP钩子 ===
        logging.info(f"[{name}] 阶段 3/4: 正在注入Shellcode并安装JMP钩子...")
        
        try:
            self.pm.write_bytes(code_cave_address, shellcode_bytes, len(shellcode_bytes))

            jmp_shellcode_asm = f"jmp {code_cave_address}"
            jmp_bytes_list, _ = self.ks.asm(jmp_shellcode_asm, addr=instruction_address)
            if jmp_bytes_list is None:
                raise keystone.KsError("Keystone assembler returned None for JMP instruction.")
            
            jmp_bytes = bytes(jmp_bytes_list)
            
            padding_len = instruction_length - len(jmp_bytes)
            final_detour_bytes = jmp_bytes + (b'\x90' * padding_len) # NOP

            self.pm.write_bytes(instruction_address, final_detour_bytes, len(final_detour_bytes))

        except (keystone.KsError, MemoryError) as e:
            logging.error(f"[{name}] 注入或安装JMP钩子失败: {e}")
            self.pm.free(pointer_storage_address)
            self.pm.free(code_cave_address)
            return False
            
        # === 阶段 4: 完成 - 保存钩子信息 ===
        hook_info = {
            "name": name,
            "instruction_address": instruction_address,
            "original_bytes": original_bytes,
            "pointer_storage_address": pointer_storage_address,
            "code_cave_address": code_cave_address,
        }
        self.installed_hooks[name] = hook_info
        
        logging.info(f"名为 '{name}' 的钩子已成功安装！")
        return True

    def get_captured_pointer(self, name: str) -> int:
        """
        获取由我们的钩子捕获到的指针。

        :param name: 钩子的名称。
        :return: 捕获到的指针地址，如果钩子未安装或未捕获到，则返回 0。
        """
        hook_info = self.installed_hooks.get(name)
        if not hook_info:
            logging.warning(f"名为 '{name}' 的钩子不存在。")
            return 0

        pointer_storage_address = hook_info.get("pointer_storage_address")
        if not pointer_storage_address:
            return 0
            
        try:
            read_ptr = self.pm.read_longlong if self.is_64bit else self.pm.read_int
            captured_ptr = read_ptr(pointer_storage_address)
            return int(captured_ptr)
        except (MemoryError, TypeError) as e:
            logging.error(f"读取捕获的指针时发生内存错误: {e}")
            return 0

    def uninstall_hook(self, name: str) -> bool:
        """
        卸载一个已安装的钩子，恢复所有被修改的代码和内存。

        :param name: 要卸载的钩子的名称。
        :return: 卸载成功返回 True，否则返回 False。
        """
        hook_info = self.installed_hooks.get(name)
        if not hook_info:
            logging.warning(f"尝试卸载一个不存在的钩子: '{name}'")
            return False

        logging.info(f"正在卸载名为 '{name}' 的钩子...")
        
        try:
            # 1. 恢复原始指令
            original_bytes = hook_info["original_bytes"]
            address = hook_info["instruction_address"]
            self.pm.write_bytes(address, original_bytes, len(original_bytes))
            
            # 2. 释放分配的内存
            self.pm.free(hook_info["pointer_storage_address"])
            self.pm.free(hook_info["code_cave_address"])

            # 3. 从字典中移除
            del self.installed_hooks[name]
            logging.info(f"钩子 '{name}' 已成功卸载。")
            return True

        except (KeyError, MemoryError) as e:
            logging.error(f"卸载钩子 '{name}' 时发生错误: {e}")
            return False

    def uninstall_all_hooks(self):
        """卸载所有已安装的钩子。"""
        # 使用list转换以避免在迭代时修改字典
        for name in list(self.installed_hooks.keys()):
            self.uninstall_hook(name)

    def __del__(self):
        """确保在对象销毁时清理所有钩子。"""
        self.uninstall_all_hooks()

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    logging.info("CodeCaveHooker 模块已创建。这是一个高级功能的占位符。")
    # 可以在这里添加更详细的独立测试... 