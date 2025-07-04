from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLineEdit, QPushButton,
                             QTextEdit, QLabel, QMessageBox, QFormLayout, QComboBox, QInputDialog)
from PyQt5.QtCore import Qt
import logging

from core.advanced_scanner import AdvancedScanner
from core.structure_manager import StructureManager

class DisasmTab(QWidget):
    """简单反汇编浏览器：
    1. 输入地址 + 大小，展示十六进制字节和 Capstone 反汇编结果。
    2. 点击"生成 AOB finder"自动分析 mov/lea [rip+??] 指令并写入 YAML。
       （当前仅生成弹窗文本，由用户复制粘贴到 definitions.yaml）
    """

    def __init__(self, scanner: AdvancedScanner | None = None, structure_manager: StructureManager | None = None, parent=None):
        super().__init__(parent)
        self.scanner: AdvancedScanner | None = scanner
        self.structure_manager: StructureManager | None = structure_manager
        self.init_ui()

    # -------------------------------------------------
    def init_ui(self):
        main_layout = QVBoxLayout(self)

        form = QFormLayout()
        self.addr_input = QLineEdit()
        self.addr_input.setPlaceholderText("例如: 0x140123456")
        self.size_input = QLineEdit("32")
        form.addRow("地址:", self.addr_input)
        form.addRow("大小(bytes):", self.size_input)

        btn_layout = QHBoxLayout()
        self.disasm_btn = QPushButton("反汇编")
        self.disasm_btn.clicked.connect(self.perform_disasm)
        self.generate_btn = QPushButton("生成 AOB finder")
        self.generate_btn.clicked.connect(self.generate_finder)
        btn_layout.addWidget(self.disasm_btn)
        btn_layout.addWidget(self.generate_btn)
        btn_layout.addStretch(1)

        self.output = QTextEdit()
        self.output.setReadOnly(True)

        main_layout.addLayout(form)
        main_layout.addLayout(btn_layout)
        main_layout.addWidget(self.output)

        self.setLayout(main_layout)

    # -------------------------------------------------
    def set_scanner(self, scanner: AdvancedScanner):
        self.scanner = scanner

    def set_structure_manager(self, manager: StructureManager):
        self.structure_manager = manager

    def perform_disasm(self):
        if not self.scanner:
            QMessageBox.warning(self, "错误", "请先附加到进程。")
            return
        try:
            addr = int(self.addr_input.text(), 16)
            size = int(self.size_input.text())
        except ValueError:
            QMessageBox.warning(self, "错误", "地址或大小格式不正确。")
            return

        instrs = self.scanner.disasm_block(addr, size)
        if not instrs:
            self.output.setText("<无法读取或无指令>")
            return

        lines = []
        bytes_data = self.scanner.read_bytes(addr, size)
        lines.append("Bytes: " + bytes_data.hex(" "))
        lines.append("\nDisasm:")
        for ins in instrs:
            lines.append(f"{ins.address:016X}: {ins.mnemonic} {ins.op_str}")
        self.output.setText("\n".join(lines))

    def generate_finder(self):
        if not self.scanner:
            QMessageBox.warning(self, "错误", "请先附加到进程。")
            return
        try:
            addr = int(self.addr_input.text(), 16)
        except ValueError:
            QMessageBox.warning(self, "错误", "请先输入有效地址并反汇编。")
            return
        instrs = self.scanner.disasm_block(addr, 16)
        if not instrs:
            QMessageBox.warning(self, "错误", "当前地址无有效指令。")
            return
        ins = instrs[0]
        # 仅处理典型 mov/lea rip+off
        if "rip" not in ins.op_str:
            QMessageBox.information(self, "提示", "首条指令不包含 RIP 相对寻址，无法自动计算。")
            return
        # 计算 rip_offset = 操作数开始处索引
        rip_offset = 3  # 大多数 48 8B 05 ?? ?? ?? ??
        instr_size = ins.size
        # 生成 AOB 字符串（将 4 字节偏移部分替换 ??）
        bytes_raw = self.scanner.read_bytes(ins.address, instr_size)
        aob_parts = []
        for i, b in enumerate(bytes_raw):
            if rip_offset <= i < rip_offset + 4:
                aob_parts.append("??")
            else:
                aob_parts.append(f"{b:02X}")
        aob_str = " ".join(aob_parts)

        # ---- 自动写入 definitions.yaml if possible ----
        if not self.structure_manager:
            QMessageBox.information(self, "AOB finder", "未绑定 StructureManager，无法写入 definitions.yaml。\n\n生成的 finder 字段:\n" + aob_str)
            return

        # 询问结构体名称
        struct_name, ok = QInputDialog.getText(self, "结构体名称", "填写或选择要写入的结构体:")
        if not ok or not struct_name:
            return

        # 构建 finder dict
        finder_dict = {
            'aob': aob_str,
            'rip_offset': rip_offset,
            'instr_size': instr_size,
            'deref': True
        }

        if struct_name in self.structure_manager.definitions:
            self.structure_manager.definitions[struct_name]['finder'] = finder_dict
        else:
            # 询问成员信息
            member_name, ok1 = QInputDialog.getText(self, "成员名称", "输入成员名称(默认 Value):", text="Value")
            if not ok1 or not member_name:
                member_name = "Value"
            type_choice, ok2 = QInputDialog.getItem(self, "类型选择", "选择数据类型:",
                                                   ["int", "float", "double", "ulong", "bool", "byte", "string"], 0, False)
            if not ok2:
                type_choice = "int"

            self.structure_manager.definitions[struct_name] = {
                'finder': finder_dict,
                'members': {
                    member_name: {'offset': 0, 'type': type_choice}
                }
            }

        # 保存并提示
        try:
            self.structure_manager.save_definitions()
            QMessageBox.information(self, "成功", f"finder 已写入结构体 '{struct_name}' 并保存 definitions.yaml。")
        except Exception as e:
            QMessageBox.warning(self, "写入失败", f"保存 definitions.yaml 时出错:\n{e}")

    def refresh(self):
        """刷新反汇编标签页的状态"""
        if not self.scanner or not self.structure_manager:
            return
            
        try:
            # 保存当前输入
            current_address = self.addr_input.text()
            current_size = self.size_input.text()
            
            # 如果有地址和大小，重新执行反汇编
            if current_address and current_size:
                try:
                    addr = int(current_address, 16)
                    size = int(current_size)
                    self.perform_disasm()
                except ValueError:
                    pass  # 忽略无效的输入值
        except Exception as e:
            logging.error(f"刷新反汇编标签页失败: {e}")
            raise 