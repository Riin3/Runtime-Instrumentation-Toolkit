from PyQt5.QtWidgets import (
    QDialog, QVBoxLayout, QLineEdit, QPushButton, QLabel, QMessageBox, 
    QFormLayout, QComboBox
)
from typing import Optional, Dict

class AOBBuilderDialog(QDialog):
    """
    一个用于通过AOB扫描快速构建结构体的对话框。
    """
    def __init__(self, available_structures: Dict[str, any], parent=None):
        super().__init__(parent)
        self.setWindowTitle("从AOB构建结构体")
        self.setMinimumWidth(400)

        self.available_structures = available_structures
        self.result = None

        # --- UI Elements ---
        self.layout = QVBoxLayout(self)
        self.form_layout = QFormLayout()

        self.structure_selector = QComboBox(self)
        self.structure_selector.addItems(self.available_structures.keys())

        self.build_button = QPushButton("构建", self)
        self.build_button.clicked.connect(self.accept)

        # --- Layout ---
        self.form_layout.addRow(QLabel("目标结构体:"), self.structure_selector)
        
        self.layout.addLayout(self.form_layout)
        self.layout.addWidget(self.build_button)

    def get_inputs(self) -> Optional[Dict[str, str]]:
        """
        获取用户输入。如果输入有效，则返回一个包含所有输入的字典。
        """
        selected_structure = self.structure_selector.currentText()

        if not selected_structure:
            QMessageBox.warning(self, "输入错误", "目标结构体不能为空。")
            return None
        
        return {
            "structure_name": selected_structure
        }

    def accept(self):
        """
        当用户点击“构建”时，验证输入并关闭对话框。
        """
        self.result = self.get_inputs()
        if self.result:
            super().accept()