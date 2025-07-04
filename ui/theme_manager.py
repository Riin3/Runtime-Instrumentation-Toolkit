from PyQt5.QtWidgets import QApplication
from PyQt5.QtGui import QPalette, QColor
from PyQt5.QtCore import Qt
import json
import os
import logging

class ThemeManager:
    """主题管理器，负责应用和管理应用程序的主题"""
    
    # 默认主题定义
    LIGHT_THEME = {
        'window': {
            'background': '#FFFFFF',
            'text': '#000000'
        },
        'sidebar': {
            'background': '#F0F0F0',
            'text': '#000000',
            'border': '#D0D0D0'
        },
        'toolbar': {
            'background': '#F5F5F5',
            'text': '#000000',
            'border': '#D0D0D0',
            'button_hover': '#E0E0E0'
        },
        'table': {
            'background': '#FFFFFF',
            'alternate_background': '#F9F9F9',
            'text': '#000000',
            'grid': '#E0E0E0',
            'header_background': '#F0F0F0',
            'header_text': '#000000',
            'selection_background': '#0078D7',
            'selection_text': '#FFFFFF'
        },
        'editor': {
            'background': '#FFFFFF',
            'text': '#000000',
            'line_number_background': '#F0F0F0',
            'line_number_text': '#707070',
            'current_line': '#F8F8F8'
        }
    }
    
    DARK_THEME = {
        'window': {
            'background': '#2D2D2D',
            'text': '#FFFFFF'
        },
        'sidebar': {
            'background': '#252526',
            'text': '#FFFFFF',
            'border': '#1E1E1E'
        },
        'toolbar': {
            'background': '#333333',
            'text': '#FFFFFF',
            'border': '#1E1E1E',
            'button_hover': '#404040'
        },
        'table': {
            'background': '#2D2D2D',
            'alternate_background': '#252526',
            'text': '#FFFFFF',
            'grid': '#404040',
            'header_background': '#333333',
            'header_text': '#FFFFFF',
            'selection_background': '#0C7CD5',
            'selection_text': '#FFFFFF'
        },
        'editor': {
            'background': '#1E1E1E',
            'text': '#FFFFFF',
            'line_number_background': '#252526',
            'line_number_text': '#858585',
            'current_line': '#282828'
        }
    }
    
    def __init__(self):
        self.current_theme = 'light'
        self.themes = {
            'light': self.LIGHT_THEME,
            'dark': self.DARK_THEME
        }
        self.load_custom_themes()
    
    def load_custom_themes(self):
        """从配置文件加载自定义主题"""
        try:
            config_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'config')
            theme_file = os.path.join(config_dir, 'themes.json')
            
            if os.path.exists(theme_file):
                with open(theme_file, 'r', encoding='utf-8') as f:
                    custom_themes = json.load(f)
                self.themes.update(custom_themes)
        except Exception as e:
            logging.error(f"加载自定义主题失败: {e}")
    
    def save_custom_themes(self):
        """保存自定义主题到配置文件"""
        try:
            config_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'config')
            os.makedirs(config_dir, exist_ok=True)
            
            theme_file = os.path.join(config_dir, 'themes.json')
            with open(theme_file, 'w', encoding='utf-8') as f:
                json.dump(self.themes, f, indent=4)
        except Exception as e:
            logging.error(f"保存自定义主题失败: {e}")
    
    def add_theme(self, name: str, theme_data: dict):
        """添加新的主题"""
        self.themes[name] = theme_data
        self.save_custom_themes()
    
    def remove_theme(self, name: str):
        """删除主题"""
        if name in ['light', 'dark']:
            raise ValueError("不能删除内置主题")
        if name in self.themes:
            del self.themes[name]
            self.save_custom_themes()
    
    def get_theme(self, name: str) -> dict:
        """获取指定主题的配置"""
        return self.themes.get(name, self.LIGHT_THEME)
    
    def apply_theme(self, name: str):
        """应用指定的主题"""
        if name not in self.themes:
            logging.error(f"主题 '{name}' 不存在")
            return
            
        self.current_theme = name
        theme = self.themes[name]
        
        # 创建调色板
        palette = QPalette()
        
        # 设置窗口颜色
        palette.setColor(QPalette.Window, QColor(theme['window']['background']))
        palette.setColor(QPalette.WindowText, QColor(theme['window']['text']))
        
        # 设置基础颜色
        palette.setColor(QPalette.Base, QColor(theme['table']['background']))
        palette.setColor(QPalette.AlternateBase, QColor(theme['table']['alternate_background']))
        palette.setColor(QPalette.Text, QColor(theme['table']['text']))
        
        # 设置按钮颜色
        palette.setColor(QPalette.Button, QColor(theme['toolbar']['background']))
        palette.setColor(QPalette.ButtonText, QColor(theme['toolbar']['text']))
        
        # 设置高亮颜色
        palette.setColor(QPalette.Highlight, QColor(theme['table']['selection_background']))
        palette.setColor(QPalette.HighlightedText, QColor(theme['table']['selection_text']))
        
        # 应用调色板
        QApplication.instance().setPalette(palette)
        
        # 生成并应用样式表
        style_sheet = self._generate_style_sheet(theme)
        QApplication.instance().setStyleSheet(style_sheet)
    
    def _generate_style_sheet(self, theme: dict) -> str:
        """生成主题的样式表"""
        return f"""
            /* 主窗口 */
            QMainWindow, QDialog {{
                background-color: {theme['window']['background']};
                color: {theme['window']['text']};
            }}
            
            /* 工具栏 */
            QToolBar {{
                background-color: {theme['toolbar']['background']};
                border-bottom: 1px solid {theme['toolbar']['border']};
                spacing: 5px;
                padding: 2px;
            }}
            
            QToolBar QToolButton {{
                background-color: transparent;
                border: 1px solid transparent;
                border-radius: 2px;
                padding: 3px;
                color: {theme['toolbar']['text']};
            }}
            
            QToolBar QToolButton:hover {{
                background-color: {theme['toolbar']['button_hover']};
                border: 1px solid {theme['toolbar']['border']};
            }}
            
            QToolBar QToolButton:pressed {{
                background-color: {theme['table']['selection_background']};
                color: {theme['table']['selection_text']};
            }}
            
            /* 菜单 */
            QMenuBar {{
                background-color: {theme['toolbar']['background']};
                color: {theme['toolbar']['text']};
            }}
            
            QMenuBar::item:selected {{
                background-color: {theme['toolbar']['button_hover']};
            }}
            
            QMenu {{
                background-color: {theme['window']['background']};
                color: {theme['window']['text']};
                border: 1px solid {theme['toolbar']['border']};
            }}
            
            QMenu::item:selected {{
                background-color: {theme['table']['selection_background']};
                color: {theme['table']['selection_text']};
            }}
            
            /* 侧边栏 */
            QWidget#workspace_sidebar {{
                background-color: {theme['sidebar']['background']};
                color: {theme['sidebar']['text']};
                border-right: 1px solid {theme['sidebar']['border']};
            }}
            
            /* 表格 */
            QTableWidget, QTreeWidget, QListWidget {{
                background-color: {theme['table']['background']};
                color: {theme['table']['text']};
                gridline-color: {theme['table']['grid']};
                selection-background-color: {theme['table']['selection_background']};
                selection-color: {theme['table']['selection_text']};
                border: 1px solid {theme['toolbar']['border']};
            }}
            
            QTableWidget QHeaderView::section {{
                background-color: {theme['table']['header_background']};
                color: {theme['table']['header_text']};
                padding: 5px;
                border: none;
                border-right: 1px solid {theme['table']['grid']};
                border-bottom: 1px solid {theme['table']['grid']};
            }}
            
            /* 编辑器 */
            QPlainTextEdit, QTextEdit {{
                background-color: {theme['editor']['background']};
                color: {theme['editor']['text']};
                border: 1px solid {theme['toolbar']['border']};
                selection-background-color: {theme['table']['selection_background']};
                selection-color: {theme['table']['selection_text']};
            }}
            
            QLineEdit {{
                background-color: {theme['editor']['background']};
                color: {theme['editor']['text']};
                border: 1px solid {theme['toolbar']['border']};
                border-radius: 2px;
                padding: 2px;
                selection-background-color: {theme['table']['selection_background']};
                selection-color: {theme['table']['selection_text']};
            }}
            
            QLineEdit:focus {{
                border: 1px solid {theme['table']['selection_background']};
            }}
            
            /* 下拉框 */
            QComboBox {{
                background-color: {theme['editor']['background']};
                color: {theme['editor']['text']};
                border: 1px solid {theme['toolbar']['border']};
                border-radius: 2px;
                padding: 2px;
            }}
            
            QComboBox:hover {{
                border: 1px solid {theme['table']['selection_background']};
            }}
            
            QComboBox::drop-down {{
                border: none;
            }}
            
            QComboBox::down-arrow {{
                image: url(:/icons/down_arrow_{self.current_theme}.png);
            }}
            
            QComboBox QAbstractItemView {{
                background-color: {theme['editor']['background']};
                color: {theme['editor']['text']};
                selection-background-color: {theme['table']['selection_background']};
                selection-color: {theme['table']['selection_text']};
                border: 1px solid {theme['toolbar']['border']};
            }}
            
            /* 按钮 */
            QPushButton {{
                background-color: {theme['toolbar']['background']};
                color: {theme['toolbar']['text']};
                border: 1px solid {theme['toolbar']['border']};
                border-radius: 2px;
                padding: 5px 10px;
            }}
            
            QPushButton:hover {{
                background-color: {theme['toolbar']['button_hover']};
            }}
            
            QPushButton:pressed {{
                background-color: {theme['table']['selection_background']};
                color: {theme['table']['selection_text']};
            }}
            
            QPushButton:disabled {{
                background-color: {theme['toolbar']['background']};
                color: {theme['toolbar']['border']};
                border: 1px solid {theme['toolbar']['border']};
            }}
            
            /* 滚动条 */
            QScrollBar:vertical {{
                background-color: {theme['window']['background']};
                width: 12px;
                margin: 0px;
            }}
            
            QScrollBar::handle:vertical {{
                background-color: {theme['toolbar']['border']};
                min-height: 20px;
                border-radius: 6px;
                margin: 2px;
            }}
            
            QScrollBar::handle:vertical:hover {{
                background-color: {theme['toolbar']['button_hover']};
            }}
            
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
                height: 0px;
            }}
            
            QScrollBar:horizontal {{
                background-color: {theme['window']['background']};
                height: 12px;
                margin: 0px;
            }}
            
            QScrollBar::handle:horizontal {{
                background-color: {theme['toolbar']['border']};
                min-width: 20px;
                border-radius: 6px;
                margin: 2px;
            }}
            
            QScrollBar::handle:horizontal:hover {{
                background-color: {theme['toolbar']['button_hover']};
            }}
            
            QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{
                width: 0px;
            }}
            
            /* 标签页 */
            QTabWidget::pane {{
                border: 1px solid {theme['toolbar']['border']};
            }}
            
            QTabBar::tab {{
                background-color: {theme['toolbar']['background']};
                color: {theme['toolbar']['text']};
                padding: 5px 10px;
                border: 1px solid {theme['toolbar']['border']};
                border-bottom: none;
                border-top-left-radius: 4px;
                border-top-right-radius: 4px;
            }}
            
            QTabBar::tab:selected {{
                background-color: {theme['window']['background']};
            }}
            
            QTabBar::tab:hover:!selected {{
                background-color: {theme['toolbar']['button_hover']};
            }}
            
            /* 分组框 */
            QGroupBox {{
                background-color: transparent;
                border: 1px solid {theme['toolbar']['border']};
                border-radius: 4px;
                margin-top: 8px;
                padding-top: 8px;
            }}
            
            QGroupBox::title {{
                color: {theme['window']['text']};
                subcontrol-origin: margin;
                subcontrol-position: top left;
                left: 8px;
                padding: 0 3px;
            }}
            
            /* 状态栏 */
            QStatusBar {{
                background-color: {theme['toolbar']['background']};
                color: {theme['toolbar']['text']};
            }}
            
            QStatusBar::item {{
                border: none;
            }}
            
            /* 工具提示 */
            QToolTip {{
                background-color: {theme['window']['background']};
                color: {theme['window']['text']};
                border: 1px solid {theme['toolbar']['border']};
                padding: 2px;
            }}
            
            /* 通用控件基色 */
            QWidget {{
                background-color: {theme['window']['background']};
                color: {theme['window']['text']};
            }}
            
            /* 表格/列表交替行颜色 */
            QTableWidget::item:alternate, QTreeWidget::item:alternate, QListWidget::item:alternate {{
                background-color: {theme['table']['alternate_background']};
            }}
            
            /* 表格/列表选中行 */
            QTableWidget::item:selected, QTreeWidget::item:selected, QListWidget::item:selected {{
                background-color: {theme['table']['selection_background']};
                color: {theme['table']['selection_text']};
            }}
            
            /* 消息框 */
            QMessageBox {{
                background-color: {theme['window']['background']};
                color: {theme['window']['text']};
            }}
            
            QMessageBox QLabel {{
                color: {theme['window']['text']};
            }}
        """ 