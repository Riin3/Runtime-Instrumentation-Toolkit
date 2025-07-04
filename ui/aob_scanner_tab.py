from PyQt5.QtWidgets import QWidget, QVBoxLayout, QLabel, QLineEdit, QPushButton, QTextEdit, QApplication

class AOBScannerTab(QWidget):
    """
    AOB扫描器功能的UI面板。
    """
    def __init__(self, scanner=None, parent=None):
        super().__init__(parent)
        self.scanner = scanner
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout(self)

        # AOB输入
        aob_layout = QVBoxLayout()
        aob_label = QLabel("AOB (特征码，用空格分隔，??表示通配符):")
        self.aob_input = QLineEdit()
        self.aob_input.setPlaceholderText("例如: 48 8B 05 ?? ?? ?? ?? 48 8D 0D")
        aob_layout.addWidget(aob_label)
        aob_layout.addWidget(self.aob_input)

        # 扫描按钮
        self.scan_button = QPushButton("开始扫描")
        self.scan_button.clicked.connect(self.perform_scan)

        # 结果显示
        results_label = QLabel("扫描结果:")
        self.results_output = QTextEdit()
        self.results_output.setReadOnly(True)

        layout.addLayout(aob_layout)
        layout.addWidget(self.scan_button)
        layout.addWidget(results_label)
        layout.addWidget(self.results_output)

        self.setLayout(layout)

    def set_scanner(self, scanner):
        """
        设置用于扫描的AdvancedScanner实例。
        """
        self.scanner = scanner

    def perform_scan(self):
        """
        执行AOB扫描并显示结果。
        """
        if not self.scanner:
            self.results_output.setText("错误：请先附加到一个进程。")
            return

        aob_pattern = self.aob_input.text()
        if not aob_pattern:
            self.results_output.setText("错误：请输入AOB特征码。")
            return

        try:
            self.results_output.setText(f"正在扫描 AOB: {aob_pattern}...")
            QApplication.processEvents() # 强制UI更新

            addresses = self.scanner.aob_scan(aob_pattern)

            if addresses:
                result_text = "找到的地址:\n" + "\n".join(hex(addr) for addr in addresses)
            else:
                result_text = "未找到任何匹配的地址。"
            
            self.results_output.setText(result_text)

        except Exception as e:
            self.results_output.setText(f"扫描时发生错误: {e}")