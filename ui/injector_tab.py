from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QTextEdit, QPushButton,
                             QFileDialog, QMessageBox, QInputDialog, QLabel, QFormLayout,
                             QDialog, QLineEdit, QComboBox)
import keystone
from core.structure_manager import StructureManager
import logging

class InjectorTab(QWidget):
    def __init__(self, scanner=None, structure_manager: StructureManager | None = None, parent=None):
        super().__init__(parent)
        self.scanner = scanner
        self.structure_manager = structure_manager
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout(self)

        self.shellcode_input = QTextEdit()
        self.shellcode_input.setPlaceholderText("在此处输入或粘贴十六进制 shellcode (例如: 90 90 C3)")
        layout.addWidget(self.shellcode_input)

        button_layout = QHBoxLayout()
        self.load_button = QPushButton("从文件加载")
        self.load_button.clicked.connect(self.load_shellcode_from_file)
        self.inject_button = QPushButton("注入并执行")
        self.inject_button.clicked.connect(self.inject_shellcode)

        # quick hook button
        self.hook_button = QPushButton("Hook写静态指针")
        self.hook_button.clicked.connect(self.show_hook_dialog)

        button_layout.addWidget(self.load_button)
        button_layout.addStretch(1)
        button_layout.addWidget(self.inject_button)
        button_layout.addWidget(self.hook_button)
        layout.addLayout(button_layout)

    def set_scanner(self, scanner):
        self.scanner = scanner

    def set_structure_manager(self, mgr):
        self.structure_manager = mgr

    def load_shellcode_from_file(self):
        options = QFileDialog.Options()
        file_name, _ = QFileDialog.getOpenFileName(self, "加载 Shellcode 文件", "", "二进制文件 (*.bin);;所有文件 (*)", options=options)
        if file_name:
            try:
                with open(file_name, 'rb') as f:
                    shellcode_bytes = f.read()
                    hex_string = ' '.join(f'{b:02x}' for b in shellcode_bytes)
                    self.shellcode_input.setText(hex_string)
            except Exception as e:
                QMessageBox.critical(self, "错误", f"无法加载文件: {e}")

    def inject_shellcode(self):
        if not self.scanner or not self.scanner.pm:
            QMessageBox.warning(self, "警告", "请先附加到一个进程。")
            return

        hex_string = self.shellcode_input.toPlainText().strip()
        if not hex_string:
            QMessageBox.warning(self, "警告", "Shellcode 不能为空。")
            return

        try:
            shellcode_bytes = bytes.fromhex(hex_string.replace(' ', ''))
        except ValueError:
            QMessageBox.critical(self, "错误", "无效的十六进制字符串。请确保只包含有效的十六进制字符和空格。")
            return

        if self.scanner.inject_and_execute(shellcode_bytes):
            QMessageBox.information(self, "成功", "Shellcode 注入并执行成功！")
        else:
            QMessageBox.critical(self, "失败", "Shellcode 注入失败。请查看日志获取详细信息。")

    # ---------------- Hook wizard ----------------
    def show_hook_dialog(self):
        if not self.scanner:
            QMessageBox.warning(self, "错误", "请先附加到进程。")
            return
        dlg = HookDialog(self)
        if dlg.exec_():
            func_addr = dlg.func_addr
            reg = dlg.reg
            static_addr = dlg.static_addr
            struct_name = dlg.struct_name
            # assemble shellcode: mov [static_addr], reg ; jmp back
            ks = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_64)
            asm = f"mov [rip+0x0], {reg}\nret"
            encoding, _ = ks.asm(asm)
            shellcode = bytes(encoding) + static_addr.to_bytes(8 if self.scanner.is_64bit else 4, 'little')
            if self.scanner.inject_and_execute(shellcode):
                if self.structure_manager and struct_name:
                    self.structure_manager.definitions.setdefault(struct_name, {'members': {'Value': {'offset':0,'type':'int'}}})
                    self.structure_manager.definitions[struct_name]['finder']={'address': static_addr}
                    try:
                        self.structure_manager.save_definitions()
                    except Exception:
                        pass
                QMessageBox.information(self, "成功", "Hook 注入成功，并已更新 definitions.yaml")

    def refresh(self):
        """刷新注入器标签页的状态"""
        if not self.scanner:
            return
            
        try:
            # 保存当前输入
            current_pattern = self.pattern_edit.text()
            current_code = self.code_edit.toPlainText()
            
            # 清空结果
            self.result_list.clear()
            
            # 如果有搜索模式，重新执行搜索
            if current_pattern:
                self.search_pattern()
                
            # 恢复代码
            if current_code:
                self.code_edit.setPlainText(current_code)
        except Exception as e:
            logging.error(f"刷新注入器失败: {e}")
            raise

class HookDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Hook 写静态指针")
        form=QFormLayout(self)
        self.func_input=QLineEdit(self)
        self.reg_input=QComboBox(self)
        self.reg_input.addItems(["rax","rcx","rdx","r8","r9","rdi","rsi"])
        self.static_input=QLineEdit(self)
        self.struct_input=QLineEdit(self)
        form.addRow("函数地址:",self.func_input)
        form.addRow("寄存器:",self.reg_input)
        form.addRow("静态指针地址:",self.static_input)
        form.addRow("结构体名称:",self.struct_input)
        btn=QPushButton("确认",self)
        btn.clicked.connect(self.accept)
        form.addRow(btn)
    def accept(self):
        try:
            self.func_addr=int(self.func_input.text(),16)
            self.static_addr=int(self.static_input.text(),16)
            self.reg=self.reg_input.currentText()
            self.struct_name=self.struct_input.text()
        except ValueError:
            QMessageBox.warning(self,"错误","输入地址必须是16进制")
            return
        super().accept()