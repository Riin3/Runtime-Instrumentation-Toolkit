import pymem
import logging
import os
import sys
import time
import ctypes
from ctypes import wintypes

# 将主目录添加到sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.advanced_scanner import AdvancedScanner
from core.hook_manager import HookManager, CONTEXT, EXCEPTION_POINTERS, DR7_BREAK_ON_WRITE, EXCEPTION_CONTINUE_SEARCH

from pymem.exception import ProcessNotFound

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


logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# 我们在 investigate_unity_player.py 中找到的静态指针地址
STATIC_POINTER_ADDRESS = 0x7ffdd87a1960
g_game_manager_base = 0
g_hook_should_stop = False


def _get_thread_ids_for_process(pid: int) -> list[int]:
    thread_ids = []
    h_snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)
    if h_snapshot == INVALID_HANDLE_VALUE:
        return thread_ids
    
    entry = THREADENTRY32()
    entry.dwSize = ctypes.sizeof(THREADENTRY32)
    
    if kernel32.Thread32First(h_snapshot, ctypes.byref(entry)):
        while True:
            if entry.th32OwnerProcessID == pid:
                thread_ids.append(entry.th32ThreadID)
            if not kernel32.Thread32Next(h_snapshot, ctypes.byref(entry)):
                break
    
    kernel32.CloseHandle(h_snapshot)
    return thread_ids


def on_write_to_static_pointer(context_ptr: EXCEPTION_POINTERS) -> int:
    """
    当游戏向 GameObjectManager 静态指针写入数据时，此函数将被调用。
    """
    global g_game_manager_base, g_hook_should_stop
    
    if g_hook_should_stop:
        return EXCEPTION_CONTINUE_SEARCH

    context = context_ptr.contents.ContextRecord.contents
    
    # 我们需要找到是哪条指令触发了写入，并从哪个寄存器获取了值。
    # 这需要一些调试，但通常 MOV [address], REG 指令会使用 RAX, RCX, RDX 等。
    # 我们先假设值在 RAX 中。
    written_value = context.Rax
    
    logging.info("="*50)
    logging.info(f"硬件断点命中！游戏正在向静态地址 {hex(STATIC_POINTER_ADDRESS)} 写入数据。")
    logging.info(f"捕获到的指令指针 (RIP): {hex(context.Rip)}")
    logging.info(f"捕获到的RAX寄存器值: {hex(written_value)}")
    logging.info("="*50)
    
    if written_value:
        g_game_manager_base = written_value
        g_hook_should_stop = True # 发出信号，我们已捕获到所需数据
        logging.info(f"成功捕获 GameObjectManager 基地址: {hex(g_game_manager_base)}")

    return EXCEPTION_CONTINUE_SEARCH

def main():
    try:
        pm = pymem.Pymem("Yokai Art.exe")
        hook_manager = HookManager(pm)
        logging.info("成功附加到进程: Yokai Art.exe")
    except ProcessNotFound:
        logging.error("错误: 未找到进程 'Yokai Art.exe'。请先运行游戏。")
        return

    if not pm.process_id:
        logging.error("无法获取进程ID。")
        return
        
    thread_ids = _get_thread_ids_for_process(pm.process_id)
    if not thread_ids:
        logging.error("无法获取目标进程的线程列表。")
        return

    logging.info(f"将在静态指针地址 {hex(STATIC_POINTER_ADDRESS)} 为 {len(thread_ids)} 个线程设置硬件写断点。")
    
    # 为所有线程设置硬件断点
    # 注意：我们应该在进入游戏的关键代码执行前设置好断点
    with hook_manager:
        hook_manager.hw_breakpoint_callback = on_write_to_static_pointer
        for tid in thread_ids:
            hook_manager.set_hardware_breakpoint(STATIC_POINTER_ADDRESS, tid, DR7_BREAK_ON_WRITE)
        
        logging.info("断点已设置。请在游戏中进行操作（例如：进入主菜单，开始游戏）以触发指针初始化。")
        logging.info("测试将在30秒后超时...")

        # 等待回调函数设置全局变量
        timeout = 30
        start_time = time.time()
        while not g_game_manager_base and time.time() - start_time < timeout:
            time.sleep(1)

    # 上下文管理器退出时，断点会自动移除
    
    if g_game_manager_base:
        logging.info(f"测试成功！最终获取到的 GameObjectManager 基地址是: {hex(g_game_manager_base)}")
    else:
        logging.error("测试失败，超时仍未捕获到 GameObjectManager 基地址。")
        
if __name__ == "__main__":
    main() 