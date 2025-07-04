from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QLabel, 
                            QTreeWidget, QTreeWidgetItem, QPushButton,
                            QFrame, QHBoxLayout)
from PyQt5.QtCore import Qt, QTimer

class WorkspaceSidebar(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.init_ui()
        self.fps_timer = QTimer()
        self.fps_timer.timeout.connect(self.update_fps)
        self.fps_timer.start(1000)  # 每秒更新一次
        self.frame_count = 0
        self.current_fps = 0
        
    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        
        # 进程信息区域
        process_frame = QFrame()
        process_frame.setFrameStyle(QFrame.StyledPanel)
        process_layout = QVBoxLayout(process_frame)
        
        self.process_name_label = QLabel("进程: 未附加")
        self.process_id_label = QLabel("PID: -")
        self.base_address_label = QLabel("基址: 0x00000000")
        
        process_layout.addWidget(self.process_name_label)
        process_layout.addWidget(self.process_id_label)
        process_layout.addWidget(self.base_address_label)
        
        # 性能监控区域
        perf_frame = QFrame()
        perf_frame.setFrameStyle(QFrame.StyledPanel)
        perf_layout = QVBoxLayout(perf_frame)
        
        self.fps_label = QLabel("刷新率: 0 FPS")
        perf_layout.addWidget(self.fps_label)
        
        # 结构体树
        struct_frame = QFrame()
        struct_frame.setFrameStyle(QFrame.StyledPanel)
        struct_layout = QVBoxLayout(struct_frame)
        
        struct_header = QHBoxLayout()
        struct_title = QLabel("已加载结构体")
        refresh_button = QPushButton("刷新")
        refresh_button.clicked.connect(self.refresh_structures)
        struct_header.addWidget(struct_title)
        struct_header.addWidget(refresh_button)
        
        self.struct_tree = QTreeWidget()
        self.struct_tree.setHeaderHidden(True)
        
        struct_layout.addLayout(struct_header)
        struct_layout.addWidget(self.struct_tree)
        
        # 添加所有区域到主布局
        layout.addWidget(process_frame)
        layout.addWidget(perf_frame)
        layout.addWidget(struct_frame)
        layout.addStretch()
        
        self.setMinimumWidth(200)
        self.setMaximumWidth(300)
    
    def update_process_info(self, name=None, pid=None, base_addr=None):
        if name:
            self.process_name_label.setText(f"进程: {name}")
        if pid:
            self.process_id_label.setText(f"PID: {pid}")
        if base_addr:
            self.base_address_label.setText(f"基址: {hex(base_addr)}")
    
    def update_structures(self, structures):
        self.struct_tree.clear()
        for struct_name, struct_info in structures.items():
            item = QTreeWidgetItem([struct_name])
            if hasattr(struct_info, 'base_address'):
                addr_item = QTreeWidgetItem([f"基址: {hex(struct_info.base_address)}"])
                item.addChild(addr_item)
            self.struct_tree.addTopLevelItem(item)
    
    def refresh_structures(self):
        # 这个方法将由主窗口连接并实现
        pass
    
    def increment_frame(self):
        self.frame_count += 1
    
    def update_fps(self):
        self.current_fps = self.frame_count
        self.fps_label.setText(f"刷新率: {self.current_fps} FPS")
        self.frame_count = 0 