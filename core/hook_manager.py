import ctypes
from ctypes import wintypes
import logging
from threading import Event
from dataclasses import dataclass, field
from typing import Callable, Optional

# Windows API 常量
CONTEXT_AMD64 = 0x100000
CONTEXT_CONTROL = CONTEXT_AMD64 | 0x1
CONTEXT_INTEGER = CONTEXT_AMD64 | 0x2
CONTEXT_SEGMENTS = CONTEXT_AMD64 | 0x4
CONTEXT_FLOATING_POINT = CONTEXT_AMD64 | 0x8
CONTEXT_DEBUG_REGISTERS = CONTEXT_AMD64 | 0x10
CONTEXT_FULL = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_FLOATING_POINT
CONTEXT_ALL = CONTEXT_FULL | CONTEXT_SEGMENTS | CONTEXT_DEBUG_REGISTERS

EXCEPTION_CONTINUE_EXECUTION = -1 # 0xFFFFFFFF
EXCEPTION_CONTINUE_SEARCH = 0x0
STATUS_SINGLE_STEP = 0x80000004

DBG_CONTINUE = 0x00010002
DBG_EXCEPTION_NOT_HANDLED = 0x80010001

# 硬件断点相关
DR7_LOCAL_ENABLE_SHIFT = 0
DR7_GLOBAL_ENABLE_SHIFT = 1
DR7_BREAK_ON_EXECUTION = 0
DR7_BREAK_ON_WRITE = 1
DR7_BREAK_ON_READWRITE = 3
DR7_LEN_1 = 0
DR7_LEN_2 = 1
DR7_LEN_4 = 3
DR7_LEN_8 = 2

# Windows 数据结构
class M128A(ctypes.Structure):
    _fields_ = [
        ("Low", wintypes.ULARGE_INTEGER),
        ("High", wintypes.ULARGE_INTEGER)
    ]

class CONTEXT(ctypes.Structure):
    _fields_ = [
        ("P1Home", ctypes.c_ulonglong),
        ("P2Home", ctypes.c_ulonglong),
        ("P3Home", ctypes.c_ulonglong),
        ("P4Home", ctypes.c_ulonglong),
        ("P5Home", ctypes.c_ulonglong),
        ("P6Home", ctypes.c_ulonglong),
        ("ContextFlags", wintypes.DWORD),
        ("MxCsr", wintypes.DWORD),
        ("SegCs", wintypes.WORD),
        ("SegDs", wintypes.WORD),
        ("SegEs", wintypes.WORD),
        ("SegFs", wintypes.WORD),
        ("SegGs", wintypes.WORD),
        ("SegSs", wintypes.WORD),
        ("EFlags", wintypes.DWORD),
        ("Dr0", ctypes.c_ulonglong),
        ("Dr1", ctypes.c_ulonglong),
        ("Dr2", ctypes.c_ulonglong),
        ("Dr3", ctypes.c_ulonglong),
        ("Dr6", ctypes.c_ulonglong),
        ("Dr7", ctypes.c_ulonglong),
        ("Rax", ctypes.c_ulonglong),
        ("Rcx", ctypes.c_ulonglong),
        ("Rdx", ctypes.c_ulonglong),
        ("Rbx", ctypes.c_ulonglong),
        ("Rsp", ctypes.c_ulonglong),
        ("Rbp", ctypes.c_ulonglong),
        ("Rsi", ctypes.c_ulonglong),
        ("Rdi", ctypes.c_ulonglong),
        ("R8", ctypes.c_ulonglong),
        ("R9", ctypes.c_ulonglong),
        ("R10", ctypes.c_ulonglong),
        ("R11", ctypes.c_ulonglong),
        ("R12", ctypes.c_ulonglong),
        ("R13", ctypes.c_ulonglong),
        ("R14", ctypes.c_ulonglong),
        ("R15", ctypes.c_ulonglong),
        ("Rip", ctypes.c_ulonglong),
        ("FltSave", M128A),
        ("VectorRegister", M128A * 26),
        ("VectorControl", ctypes.c_ulonglong),
        ("DebugControl", ctypes.c_ulonglong),
        ("LastBranchToRip", ctypes.c_ulonglong),
        ("LastBranchFromRip", ctypes.c_ulonglong),
        ("LastExceptionToRip", ctypes.c_ulonglong),
        ("LastExceptionFromRip", ctypes.c_ulonglong)
    ]

class EXCEPTION_RECORD(ctypes.Structure):
    pass

EXCEPTION_RECORD._fields_ = [
    ("ExceptionCode", wintypes.DWORD),
    ("ExceptionFlags", wintypes.DWORD),
    ("ExceptionRecord", ctypes.POINTER(EXCEPTION_RECORD)),
    ("ExceptionAddress", wintypes.LPVOID),
    ("NumberParameters", wintypes.DWORD),
    ("ExceptionInformation", ctypes.c_ulonglong * 15)
]

class EXCEPTION_POINTERS(ctypes.Structure):
    _fields_ = [
        ("ExceptionRecord", ctypes.POINTER(EXCEPTION_RECORD)),
        ("ContextRecord", ctypes.POINTER(CONTEXT))
    ]

# 定义回调函数原型
PVECTORED_EXCEPTION_HANDLER = ctypes.WINFUNCTYPE(wintypes.LONG, ctypes.POINTER(EXCEPTION_POINTERS))

# Kernel32 函数
kernel32 = ctypes.windll.kernel32
kernel32.AddVectoredExceptionHandler.argtypes = [wintypes.ULONG, PVECTORED_EXCEPTION_HANDLER]
kernel32.AddVectoredExceptionHandler.restype = wintypes.LPVOID
kernel32.RemoveVectoredExceptionHandler.argtypes = [wintypes.LPVOID]
kernel32.RemoveVectoredExceptionHandler.restype = wintypes.ULONG
kernel32.GetThreadContext.argtypes = [wintypes.HANDLE, ctypes.POINTER(CONTEXT)]
kernel32.GetThreadContext.restype = wintypes.BOOL
kernel32.SetThreadContext.argtypes = [wintypes.HANDLE, ctypes.POINTER(CONTEXT)]
kernel32.SetThreadContext.restype = wintypes.BOOL
kernel32.OpenThread.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
kernel32.OpenThread.restype = wintypes.HANDLE
kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
kernel32.CloseHandle.restype = wintypes.BOOL
kernel32.GetCurrentThreadId.restype = wintypes.DWORD
kernel32.GetCurrentThreadId.argtypes = []

THREAD_ALL_ACCESS = 0x1F0FFF

@dataclass
class Breakpoint:
    """用一个类来封装断点的所有信息，更清晰"""
    address: int
    break_on: int
    length: int
    callback: Optional[Callable]
    tid: Optional[int] = None
    dr_index: Optional[int] = None
    original_dr7: int = 0
    active: bool = field(default=True)

class HookManager:
    def __init__(self, pm):
        self.pm = pm
        self.veh_handle = None
        self.breakpoints = {} # address -> Breakpoint object
        self.active_breakpoints_by_tid = {} # tid -> {dr_index: Breakpoint}
        self.capture_event = Event()
        self.captured_data = None

    def _get_free_dr_index(self, tid):
        if tid not in self.active_breakpoints_by_tid:
            self.active_breakpoints_by_tid[tid] = {}
        
        for i in range(4):
            if i not in self.active_breakpoints_by_tid[tid]:
                return i
        return None

    def _set_breakpoint_for_thread(self, bp: Breakpoint, tid: int):
        """为单个线程设置硬件断点"""
        dr_index = self._get_free_dr_index(tid)
        if dr_index is None:
            return False

        h_thread = kernel32.OpenThread(THREAD_ALL_ACCESS, False, tid)
        if not h_thread:
            if ctypes.get_last_error() == 87: # ERROR_INVALID_PARAMETER
                 return True
            logging.debug(f"打开线程 {tid} 失败: {ctypes.get_last_error()}")
            return False

        context = CONTEXT()
        context.ContextFlags = CONTEXT_DEBUG_REGISTERS

        if not kernel32.GetThreadContext(h_thread, ctypes.byref(context)):
            logging.debug(f"获取线程 {tid} 上下文失败: {ctypes.get_last_error()}")
            kernel32.CloseHandle(h_thread)
            return False

        bp.tid = tid
        bp.dr_index = dr_index
        bp.original_dr7 = context.Dr7

        if dr_index == 0: context.Dr0 = bp.address
        elif dr_index == 1: context.Dr1 = bp.address
        elif dr_index == 2: context.Dr2 = bp.address
        elif dr_index == 3: context.Dr3 = bp.address

        context.Dr7 |= (1 << (dr_index * 2))
        pos = 16 + (dr_index * 4)
        context.Dr7 |= (bp.break_on << pos)
        context.Dr7 |= (bp.length << (pos + 2))

        if not kernel32.SetThreadContext(h_thread, ctypes.byref(context)):
            logging.debug(f"设置线程 {tid} 上下文失败: {ctypes.get_last_error()}")
            kernel32.CloseHandle(h_thread)
            return False

        kernel32.CloseHandle(h_thread)
        self.active_breakpoints_by_tid[tid][dr_index] = bp
        return True
    
    def _remove_breakpoint_for_thread(self, bp: Breakpoint, tid: int):
        """为单个线程移除硬件断点"""
        if tid not in self.active_breakpoints_by_tid:
            return True
        
        dr_index_to_remove = -1
        for idx, active_bp in self.active_breakpoints_by_tid[tid].items():
            if active_bp.address == bp.address:
                dr_index_to_remove = idx
                break
        
        if dr_index_to_remove == -1:
            return True

        h_thread = kernel32.OpenThread(THREAD_ALL_ACCESS, False, tid)
        if not h_thread:
            logging.debug(f"打开线程 {tid} 失败 (在移除时): {ctypes.get_last_error()}")
            return False

        context = CONTEXT()
        context.ContextFlags = CONTEXT_DEBUG_REGISTERS

        if not kernel32.GetThreadContext(h_thread, ctypes.byref(context)):
            logging.debug(f"获取线程 {tid} 上下文失败 (在移除时): {ctypes.get_last_error()}")
            kernel32.CloseHandle(h_thread)
            return False

        context.Dr7 &= ~(1 << (dr_index_to_remove * 2))
        pos = 16 + (dr_index_to_remove * 4)
        context.Dr7 &= ~(0b1111 << pos)

        if dr_index_to_remove == 0: context.Dr0 = 0
        elif dr_index_to_remove == 1: context.Dr1 = 0
        elif dr_index_to_remove == 2: context.Dr2 = 0
        elif dr_index_to_remove == 3: context.Dr3 = 0
        
        context.Dr6 &= ~(1 << dr_index_to_remove)

        if not kernel32.SetThreadContext(h_thread, ctypes.byref(context)):
            logging.debug(f"设置线程 {tid} 上下文失败 (在移除时): {ctypes.get_last_error()}")
            kernel32.CloseHandle(h_thread)
            return False

        kernel32.CloseHandle(h_thread)
        
        del self.active_breakpoints_by_tid[tid][dr_index_to_remove]
        if not self.active_breakpoints_by_tid[tid]:
            del self.active_breakpoints_by_tid[tid]
            
        return True

    def set_hardware_breakpoint(self, address, break_on=DR7_BREAK_ON_WRITE, length=DR7_LEN_1, callback=None):
        """
        在所有线程上为指定地址设置硬件断点。
        断点触发后会自动移除。
        """
        if address in self.breakpoints:
            logging.warning(f"地址 {hex(address)} 的断点已存在。")
            return False
        
        logging.info(f"准备为地址 {hex(address)} 在所有线程上设置硬件断点。")
        bp = Breakpoint(address=address, break_on=break_on, length=length, callback=callback)
        self.breakpoints[address] = bp

        threads = self.pm.list_threads()
        for tid in threads:
            self._set_breakpoint_for_thread(bp, tid)
        
        logging.info(f"已尝试为 {len(threads)} 个线程在地址 {hex(address)} 设置硬件断点。")
        return True

    def remove_hardware_breakpoint(self, address):
        """在所有线程上移除指定地址的硬件断点"""
        if address not in self.breakpoints:
            logging.warning(f"无法找到要移除的断点信息: @{hex(address)}")
            return False
        
        bp = self.breakpoints[address]
        bp.active = False # 标记为非活动
        logging.info(f"准备从所有线程移除地址 {hex(address)} 上的硬件断点")

        threads = self.pm.list_threads()
        for tid in threads:
            self._remove_breakpoint_for_thread(bp, tid)

        if address in self.breakpoints:
            del self.breakpoints[address]
        logging.info(f"成功从所有线程移除了地址 {hex(address)} 上的硬件断点")
        return True

    def _veh_handler(self, exception_info_ptr):
        exception_record = exception_info_ptr.contents.ExceptionRecord.contents
        context_record = exception_info_ptr.contents.ContextRecord.contents
        exception_code = exception_record.ExceptionCode

        if exception_code == STATUS_SINGLE_STEP:
            tid = kernel32.GetCurrentThreadId()
            dr6 = context_record.Dr6
            
            triggered_dr = -1
            if dr6 & 0b1: triggered_dr = 0
            elif dr6 & 0b10: triggered_dr = 1
            elif dr6 & 0b100: triggered_dr = 2
            elif dr6 & 0b1000: triggered_dr = 3
            
            if triggered_dr != -1:
                bp = self.active_breakpoints_by_tid.get(tid, {}).get(triggered_dr)
                if bp and bp.active:
                    logging.info(f"线程 {tid} 在地址 {hex(bp.address)} 触发了硬件断点!")
                    
                    context_record.EFlags |= 0x10000 
                    context_record.Dr6 &= ~(1 << triggered_dr)

                    if bp.callback:
                        try:
                            bp.callback(context_record)
                        except Exception as e:
                            logging.error(f"硬件断点回调函数异常: {e}")
                    
                    self.remove_hardware_breakpoint(bp.address)

                    return EXCEPTION_CONTINUE_EXECUTION
        
        return EXCEPTION_CONTINUE_SEARCH

    def wait_for_capture(self, timeout=10):
        """等待硬件断点捕获到数据"""
        logging.info("等待硬件断点触发...")
        if self.capture_event.wait(timeout):
            logging.info(f"成功捕获到数据: {self.captured_data}")
            return self.captured_data
        else:
            logging.warning("等待捕获超时。")
            return None

    def __enter__(self):
        self.veh_handle = kernel32.AddVectoredExceptionHandler(1, PVECTORED_EXCEPTION_HANDLER(self._veh_handler))
        if not self.veh_handle:
            raise ctypes.WinError(ctypes.get_last_error())
        logging.info("VEH a注册成功。")
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.veh_handle:
            kernel32.RemoveVectoredExceptionHandler(self.veh_handle)
            self.veh_handle = None
        
        remaining_addresses = list(self.breakpoints.keys())
        if remaining_addresses:
            logging.info(f"清理 {len(remaining_addresses)} 个剩余的断点...")
            for address in remaining_addresses:
                self.remove_hardware_breakpoint(address)
        
        logging.info("HookManager已清理资源。")

if __name__ == '__main__':
    # 简单的测试/演示代码
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    logging.info("HookManager 模块已加载，包含Windows API定义和类结构。")
    # 在这里可以添加更多的测试逻辑
    pass 