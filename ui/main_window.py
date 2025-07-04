import os
import sys
import logging
import traceback
import subprocess
from PyQt5.QtWidgets import (QMainWindow, QWidget, QVBoxLayout, QTabWidget, 
                          QAction, QMessageBox, QFileDialog, QPushButton, 
                          QHBoxLayout, QToolBar, QLabel, QSizePolicy, QMenu, QToolButton)
from PyQt5.QtCore import QSize, QTimer
from PyQt5.QtGui import QIcon
from pymem import Pymem, exception as pymem_exception

from core.advanced_scanner import AdvancedScanner
from core.structure_manager import StructureManager
from core.code_cave_hooker import CodeCaveHooker
from ui.address_table_tab import AddressTableTab
from ui.structure_editor_tab import StructureEditorTab
from ui.injector_tab import InjectorTab
from ui.process_selector import ProcessSelectorDialog
from ui.disasm_tab import DisasmTab
from ui.workspace_sidebar import WorkspaceSidebar
from ui.theme_manager import ThemeManager
from ui.aob_builder_dialog import AOBBuilderDialog

class ModernMainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("现代化游戏内存分析工具")
        self.setGeometry(100, 100, 1200, 800)

        self.pm = None
        self.scanner = None
        self.structure_manager = None
        self.hooker = None
        
        # 初始化主题管理器
        self.theme_manager = ThemeManager()
        
        # 创建中心部件和主布局
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        self.main_layout = QHBoxLayout(self.central_widget)
        
        # 创建并添加侧边栏
        self.sidebar = WorkspaceSidebar(self)
        self.sidebar.setObjectName("workspace_sidebar")  # 用于主题样式
        self.main_layout.addWidget(self.sidebar)
        
        # 创建标签页容器
        self.tabs_container = QWidget()
        self.tabs_layout = QVBoxLayout(self.tabs_container)
        self.tabs_layout.setContentsMargins(0, 0, 0, 0)

        self.init_ui()
        self.create_toolbar()
        self.create_statusbar()
        
        # 添加标签页容器到主布局
        self.main_layout.addWidget(self.tabs_container)
        
        # 设置更新定时器
        self.update_timer = QTimer()
        self.update_timer.timeout.connect(self.update_ui)
        self.update_timer.start(16)  # ~60 FPS
        
        # 应用默认主题
        self.theme_manager.apply_theme('light')

    def init_ui(self):
        self.tabs = QTabWidget()
        self.tabs_layout.addWidget(self.tabs)

        self.address_table_tab = AddressTableTab(structure_manager=self.structure_manager)
        self.structure_editor_tab = StructureEditorTab(structure_manager=self.structure_manager, address_table=self.address_table_tab)
        self.injector_tab = InjectorTab(scanner=self.scanner)
        self.disasm_tab = DisasmTab(scanner=self.scanner, structure_manager=self.structure_manager)

        self.tabs.addTab(self.address_table_tab, "地址表")
        self.tabs.addTab(self.structure_editor_tab, "结构体编辑器")
        self.tabs.addTab(self.injector_tab, "代码注入")
        self.tabs.addTab(self.disasm_tab, "反汇编")

    def create_toolbar(self):
        """创建并配置主工具栏"""
        toolbar = QToolBar("主工具栏")
        toolbar.setIconSize(QSize(24, 24))
        self.addToolBar(toolbar)

        # 进程操作
        process_group = QWidget()
        process_layout = QHBoxLayout(process_group)
        process_layout.setContentsMargins(0, 0, 0, 0)
        process_layout.setSpacing(2)

        attach_action = QAction(QIcon.fromTheme("system-run"), "附加进程", self)
        attach_action.setStatusTip("附加到目标进程")
        attach_action.triggered.connect(self.show_process_selector)
        toolbar.addAction(attach_action)

        refresh_action = QAction(QIcon.fromTheme("view-refresh"), "刷新", self)
        refresh_action.setStatusTip("刷新所有数据")
        refresh_action.triggered.connect(self.refresh_all)
        toolbar.addAction(refresh_action)

        toolbar.addSeparator()

        # 结构体操作
        struct_action = QAction(QIcon.fromTheme("document-new"), "新建结构体", self)
        struct_action.setStatusTip("创建新的结构体定义")
        struct_action.triggered.connect(self.create_new_structure)
        toolbar.addAction(struct_action)

        toolbar.addSeparator()

        # 工具操作
        script_action = QAction(QIcon.fromTheme("system-run"), "运行脚本", self)
        script_action.setStatusTip("运行查找脚本")
        script_action.triggered.connect(self.run_find_script)
        toolbar.addAction(script_action)

        toolbar.addSeparator()

        # 主题切换按钮
        theme_button = QToolButton(self)
        theme_button.setText("主题")
        theme_button.setPopupMode(QToolButton.InstantPopup)
        theme_menu = QMenu(theme_button)
        theme_button.setMenu(theme_menu)

        light_action = QAction("浅色主题", self)
        light_action.triggered.connect(lambda: self.theme_manager.apply_theme('light'))
        theme_menu.addAction(light_action)

        dark_action = QAction("深色主题", self)
        dark_action.triggered.connect(lambda: self.theme_manager.apply_theme('dark'))
        theme_menu.addAction(dark_action)

        toolbar.addWidget(theme_button)

        # 添加一个弹性空间将状态标签推到右边
        spacer = QWidget()
        spacer.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
        toolbar.addWidget(spacer)

        self.status_label = QLabel("未附加到任何进程")
        self.status_label.setContentsMargins(0, 0, 10, 0)
        toolbar.addWidget(self.status_label)

    def show_process_selector(self):
        """
        显示进程选择对话框。
        """
        dialog = ProcessSelectorDialog(self)
        if dialog.exec_():
            selected_process = dialog.get_selected_process()
            if selected_process:
                self.attach_to_process(selected_process['pid'], selected_process['name'])

    def attach_to_process(self, pid: int, process_name: str):
        """
        附加到目标进程并初始化核心模块。
        """
        try:
            self.pm = Pymem()
            self.pm.open_process_from_id(pid)
            self.scanner = AdvancedScanner(self.pm, process_name)
            self.hooker = CodeCaveHooker(self.pm)
            definitions_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'definitions.yaml')
            self.structure_manager = StructureManager(self.pm, self.scanner, self.hooker, definitions_file=definitions_path)

            # 更新UI组件
            self.address_table_tab.set_structure_manager(self.structure_manager)
            self.address_table_tab.set_scanner(self.scanner)
            self.structure_editor_tab.set_structure_manager(self.structure_manager)
            self.injector_tab.set_scanner(self.scanner)
            self.disasm_tab.set_scanner(self.scanner)
            self.disasm_tab.set_structure_manager(self.structure_manager)

            # 更新侧边栏信息
            base_module = self.pm.base_address if hasattr(self.pm, 'base_address') else 0
            self.sidebar.update_process_info(
                name=process_name,
                pid=pid,
                base_addr=base_module
            )
            self.update_sidebar_structures()

            self.setWindowTitle(f"分析中 - {process_name} (PID: {pid})")
            self.status_label.setText(f"已附加到: {process_name}")
            self.show_status_message(f"成功附加到进程: {process_name}")
        except Exception as e:
            self.handle_attach_error(e, pid)

    def show_aob_builder(self):
        if not self.scanner or not self.structure_manager:
            self.show_error_message("请先附加到一个进程。")
            return

        dialog = AOBBuilderDialog(self.structure_manager.definitions, self)
        if dialog.exec_():
            inputs = dialog.result
            if not inputs:
                return

            # build_from_aob 已经废弃, 这个功能需要重新设计
            # 现在的逻辑是 `mount`
            QMessageBox.information(self, "功能调整", "此功能正在重构中。\n请在'结构体编辑器'选项卡中使用'挂载'功能。")
            return

            # # 2. 构建结构体
            # # build_from_aob 现在会根据 definitions.yaml 中的 aob_pattern 自动进行扫描
            # self.show_status_message(f"正在尝试通过 AOB 自动构建结构体: {inputs['structure_name']}")
            # struct_instance = self.structure_manager.build_from_aob(inputs['structure_name'])

            # if not struct_instance:
            #     self.show_error_message("构建结构体失败。请确保 definitions.yaml 中该结构体的 aob_pattern 正确，且目标进程中存在匹配项。")
            #     return

            # # 3. 在地址表中显示结果 (或新的专用UI)
            # # 暂时先添加到地址表
            # self.address_table_tab.add_entry(f"AOB_{inputs['structure_name']}", struct_instance.base_address, inputs['structure_name'])
            # self.tabs.setCurrentWidget(self.address_table_tab)
            # self.show_status_message("结构体构建成功并已添加到地址表。")

    def handle_attach_error(self, error, pid):
        self.setWindowTitle("现代化游戏内存分析工具")
        self.status_label.setText("未附加到任何进程")
        if isinstance(error, pymem_exception.ProcessNotFound):
            error_msg = f"附加到进程失败: 无法找到PID为 {pid} 的进程。"
        else:
            error_msg = f"附加到进程失败: {error}\n{traceback.format_exc()}"
        self.show_status_message(error_msg)
        logging.error(error_msg)
        self.pm = None
        self.scanner = None
        self.structure_manager = None
        self.hooker = None
        # 重置侧边栏
        self.sidebar.update_process_info()
        self.sidebar.update_structures({})

    def create_statusbar(self):
        """创建并初始化状态栏"""
        self.status_bar = self.statusBar()
        self.status_bar.showMessage("准备就绪")

    def show_status_message(self, message, timeout=5000):
        """在状态栏显示消息"""
        statusBar = self.statusBar()
        if statusBar:
            statusBar.showMessage(message, timeout)

    def run_find_script(self):
        if not self.pm or not self.pm.process_handle:
            self.show_status_message("错误: 请先附加到一个进程。")
            return

        scripts_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'scripts')
        file_path, _ = QFileDialog.getOpenFileName(self, "选择一个查找脚本", scripts_dir, "Python 脚本 (*.py)")

        if not file_path:
            return

        try:
            process_name = self.scanner.process_name if self.scanner else None
            definitions_path = self.structure_manager.definitions_file if self.structure_manager else None

            if not process_name or not definitions_path:
                self.show_status_message("错误: 进程信息不完整")
                return

            cmd = [sys.executable, file_path, process_name, definitions_path]
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=True,
                creationflags=subprocess.CREATE_NO_WINDOW
            )

            output = result.stdout.strip()
            logging.info(f"脚本 {os.path.basename(file_path)} 的输出:\n{output}")

            last_line = output.splitlines()[-1]
            if last_line.startswith("0x"):
                address = int(last_line, 16)
                QMessageBox.information(self, "脚本执行成功", f"脚本找到了一个地址: {hex(address)}\n\n我们将使用此地址加载到地址表中。")
                self.address_table_tab.load_from_struct(base_address=address)
                self.tabs.setCurrentWidget(self.address_table_tab)
            else:
                QMessageBox.information(self, "脚本执行完成", f"脚本已执行，但未找到有效的地址输出。\n\n完整输出请查看日志。")

        except FileNotFoundError:
            QMessageBox.critical(self, "错误", f"找不到 Python 解释器 '{sys.executable}'。")
        except subprocess.CalledProcessError as e:
            QMessageBox.critical(self, "脚本执行失败", f"脚本 {os.path.basename(file_path)} 执行出错:\n\n--- STDOUT ---\n{e.stdout}\n--- STDERR ---\n{e.stderr}")
        except Exception as e:
            QMessageBox.critical(self, "未知错误", f"运行脚本时发生错误: {e}")

    def update_ui(self):
        """
        定期更新UI状态
        """
        if self.pm and self.pm.process_handle:
            self.sidebar.increment_frame()
            # 可以在这里添加其他需要定期更新的UI元素

    def update_sidebar_structures(self):
        """
        更新侧边栏中的结构体列表
        """
        if self.structure_manager:
            structures = {}
            # 获取所有已加载的结构体定义
            for name in self.structure_manager.definitions:
                struct_def = self.structure_manager.definitions[name]
                structures[name] = struct_def
            self.sidebar.update_structures(structures)

    def refresh_all(self):
        """刷新所有数据"""
        if not self.pm or not self.pm.process_handle:
            self.show_status_message("错误: 未附加到进程")
            return
        
        try:
            # 刷新结构体数据
            if self.structure_manager:
                self.update_sidebar_structures()
            
            # 刷新地址表
            self.address_table_tab.refresh_all()
            
            # 刷新其他标签页
            self.structure_editor_tab.refresh()
            self.injector_tab.refresh()
            self.disasm_tab.refresh()
            
            self.show_status_message("刷新完成")
        except Exception as e:
            self.show_status_message(f"刷新失败: {e}")
            logging.error(f"刷新数据时出错: {e}")

    def create_new_structure(self):
        # 这个功能现在由 StructureEditorTab 自己处理
        self.tabs.setCurrentWidget(self.structure_editor_tab)
        self.structure_editor_tab.add_struct()

    def load_structure_file(self):
        QMessageBox.information(self, "功能变更", "结构体定义现在统一由 definitions.yaml 管理。\n您可以在'结构体编辑器'中直接修改。")

    def save_structure_file(self):
        QMessageBox.information(self, "功能变更", "结构体定义现在统一由 definitions.yaml 管理。\n在'结构体编辑器'中的修改会自动保存。")

    def closeEvent(self, event):
        reply = QMessageBox.question(self, '确认退出', '确定要退出吗？',
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if reply == QMessageBox.Yes:
            event.accept()
        else:
            event.ignore()