import psutil
import win32gui
import win32process
import win32api
import os
from win32com.shell import shell, shellcon
from PyQt5.QtWidgets import QDialog, QVBoxLayout, QListWidget, QPushButton, QListWidgetItem, QLineEdit, QHBoxLayout
from PyQt5.QtGui import QIcon
from PyQt5.QtWinExtras import QtWin
from PyQt5.QtCore import Qt, QSize

def get_icon_for_exe(exe_path):
    try:
        if not exe_path or not os.path.exists(exe_path):
            return QIcon()

        # The new implementation requires shellcon and QtWin, which need to be imported.
        # e.g.: from win32com.shell import shell, shellcon
        #       from PyQt5.QtWinExtras import QtWin
        flags = shellcon.SHGFI_ICON | shellcon.SHGFI_SMALLICON | shellcon.SHGFI_USEFILEATTRIBUTES
        ret, info = shell.SHGetFileInfo(exe_path, 0, flags)

        if not ret:
            return QIcon()

        h_icon = info[0]
        if not h_icon:
            return QIcon()

        try:
            pixmap = QtWin.fromHICON(h_icon)
            if pixmap.isNull():
                win32gui.DestroyIcon(h_icon)
                return QIcon()
            # The pixmap owns the HICON now, no need to destroy it manually if conversion is successful.
            return QIcon(pixmap)
        except Exception:
            win32gui.DestroyIcon(h_icon)
            return QIcon()

    except Exception as e:
        print(f"Error getting icon for {exe_path}: {e}")
        return QIcon()

class ProcessSelectorDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("选择进程")
        self.setGeometry(200, 200, 500, 600)
        self.selected_process = None
        self.all_processes = []

        self.init_ui()
        self.populate_processes()

    def init_ui(self):
        layout = QVBoxLayout(self)

        self.search_box = QLineEdit()
        self.search_box.setPlaceholderText("搜索进程名...")
        self.search_box.textChanged.connect(self.filter_processes)

        self.process_list = QListWidget()
        self.process_list.setIconSize(QSize(24, 24))
        self.process_list.itemDoubleClicked.connect(self.accept)

        button_layout = QHBoxLayout()
        self.ok_button = QPushButton("确定")
        self.ok_button.clicked.connect(self.accept)
        self.cancel_button = QPushButton("取消")
        self.cancel_button.clicked.connect(self.reject)
        button_layout.addWidget(self.ok_button)
        button_layout.addWidget(self.cancel_button)

        layout.addWidget(self.search_box)
        layout.addWidget(self.process_list)
        layout.addLayout(button_layout)

    def populate_processes(self):
        self.all_processes = []
        for proc in psutil.process_iter(['pid', 'name', 'exe']):
            try:
                proc_info = proc.info
                self.all_processes.append(proc_info)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass
        self.filter_processes()

    def filter_processes(self):
        search_text = self.search_box.text().lower()
        self.process_list.clear()
        for proc_info in self.all_processes:
            if search_text in proc_info['name'].lower():
                icon = get_icon_for_exe(proc_info.get('exe'))
                item = QListWidgetItem(icon, f"{proc_info['name']} (PID: {proc_info['pid']})")
                item.setData(Qt.UserRole, proc_info)
                self.process_list.addItem(item)

    def get_selected_process(self):
        selected_item = self.process_list.currentItem()
        if selected_item:
            return selected_item.data(Qt.UserRole)
        return None