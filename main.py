import sys
from PyQt5.QtWidgets import QApplication

# 从UI模块导入主窗口
from ui.main_window import ModernMainWindow

def main():
    """
    应用程序主入口。
    """
    app = QApplication(sys.argv)
    main_window = ModernMainWindow()
    main_window.show()
    sys.exit(app.exec_())

if __name__ == '__main__':
    main()