#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
应用程序工具函数
"""

import os
import sys
import logging
from pathlib import Path
from typing import Optional

def setup_logging(log_level: str = "INFO") -> logging.Logger:
    """设置日志记录"""
    logger = logging.getLogger("PointerTracker")
    logger.setLevel(getattr(logging, log_level.upper()))
    
    # 创建控制台处理器
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.DEBUG)
    
    # 创建格式器
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    console_handler.setFormatter(formatter)
    
    # 添加处理器到日志器
    if not logger.handlers:
        logger.addHandler(console_handler)
    
    return logger

def get_app_dir() -> Path:
    """获取应用程序目录"""
    return Path(__file__).parent

def get_project_root() -> Path:
    """获取项目根目录"""
    return Path(__file__).parent.parent

def ensure_dir(path: Path) -> None:
    """确保目录存在"""
    path.mkdir(parents=True, exist_ok=True)

def get_resource_path(relative_path: str) -> str:
    """获取资源文件路径（支持打包后的应用）"""
    try:
        # PyInstaller创建临时文件夹，并将路径存储在_MEIPASS中
        base_path = sys._MEIPASS
    except Exception:
        base_path = get_app_dir()
    
    return os.path.join(base_path, relative_path)

def format_bytes(bytes_value: int) -> str:
    """格式化字节数为可读字符串"""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_value < 1024.0:
            return f"{bytes_value:.1f} {unit}"
        bytes_value /= 1024.0
    return f"{bytes_value:.1f} PB"

def format_address(address: int) -> str:
    """格式化内存地址"""
    return f"0x{address:016X}"