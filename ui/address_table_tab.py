from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QTableWidget, QTableWidgetItem, QAbstractItemView,
    QPushButton, QHBoxLayout, QComboBox, QMessageBox, QLabel, QDialog,
    QLineEdit, QFormLayout, QInputDialog, QMenu, QApplication
)
from PyQt5.QtCore import QTimer, Qt
from PyQt5.QtGui import QColor
import logging

class AddressTableTab(QWidget):
    """
    地址表 (Cheat Table) 的UI面板。
    """
    def __init__(self, structure_manager=None, scanner=None, parent=None):
        super().__init__(parent)
        self.structure_manager = structure_manager
        self.scanner = scanner
        self.loaded_structures = {}
        self.init_ui()

        # 标记是否正在刷新，避免 itemChanged 循环触发
        self.is_refreshing = False

        # 定时器，用于刷新地址表中的值
        self.refresh_timer = QTimer(self)
        self.refresh_timer.timeout.connect(self.auto_refresh_values)
        self.refresh_timer.start(1000) # 每1000毫秒 (1秒) 刷新一次

    def init_ui(self):
        layout = QVBoxLayout(self)
        self.table = QTableWidget()
        self.table.setColumnCount(4)
        self.table.setHorizontalHeaderLabels(["成员", "地址", "类型", "值"])
        self.table.setEditTriggers(QAbstractItemView.DoubleClicked)
        self.table.itemChanged.connect(self.handle_item_change)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self.show_context_menu)

        # --- 工具栏 ---
        toolbar_layout = QHBoxLayout()
        self.clear_table_button = QPushButton("清空表格")
        self.clear_table_button.clicked.connect(lambda: self.table.setRowCount(0))
        toolbar_layout.addWidget(self.clear_table_button)

        self.analyze_button = QPushButton("从地址分析")
        self.analyze_button.clicked.connect(self.show_analyze_dialog)

        # 手动添加地址按钮
        self.add_address_button = QPushButton("添加地址")
        self.add_address_button.setToolTip("手动添加单个内存地址到表格")
        self.add_address_button.clicked.connect(self.show_add_address_dialog)

        # 按当前选中行快速构造结构体
        self.build_struct_button = QPushButton("构造结构体")
        self.build_struct_button.setToolTip("基于选中行自动生成结构体定义 (模块+偏移)")
        self.build_struct_button.clicked.connect(self.build_structure_from_selection)
        toolbar_layout.addWidget(self.analyze_button)
        toolbar_layout.addWidget(self.add_address_button)
        toolbar_layout.addWidget(self.build_struct_button)
        toolbar_layout.addStretch(1)

        layout.addLayout(toolbar_layout)
        layout.addWidget(self.table)
        self.setLayout(layout)

        self.populate_struct_selector()

    def set_structure_manager(self, manager):
        """
        设置StructureManager实例并更新UI。
        """
        self.structure_manager = manager
        # self.populate_struct_selector() # 不再需要，因为选择器已移除

    def set_scanner(self, scanner):
        self.scanner = scanner

    def populate_struct_selector(self):
        """
        使用StructureManager中的结构体填充下拉选择器。
        这个方法现在可以被废弃或保留用于其他目的，因为主加载流程已改变。
        """
        pass
        # self.struct_selector.clear()
        # if self.structure_manager and self.structure_manager.definitions:
        #     self.struct_selector.addItems(self.structure_manager.definitions.keys())

    def display_mounted_structure(self, struct_name, struct_instance):
        """
        公开方法：在表格中显示一个已挂载的结构体实例。
        这个方法将由 StructureEditorTab 调用。
        """
        if not struct_instance or not self.structure_manager:
            return

        self.clear_structure_display(struct_name) # 先清除旧的显示

        self.loaded_structures[struct_name] = struct_instance
        
        # 添加所有成员
        self._add_struct_members_to_table(struct_instance, struct_name)
        self.table.resizeColumnsToContents()

    def clear_structure_display(self, struct_name_to_clear):
        """
        从表格中移除特定结构体的所有条目。
        """
        if struct_name_to_clear in self.loaded_structures:
            del self.loaded_structures[struct_name_to_clear]

        rows_to_remove = []
        for row in range(self.table.rowCount()):
            item = self.table.item(row, 0)
            if item and item.text().startswith(f"{struct_name_to_clear}."):
                rows_to_remove.append(row)
        
        # 从后往前删除，避免索引变化问题
        for row in sorted(rows_to_remove, reverse=True):
            self.table.removeRow(row)

    def load_from_struct(self, base_address=None):
        if not self.structure_manager or not self.structure_manager.pm:
            QMessageBox.warning(self, "错误", "请先附加到一个进程。")
            return

        if base_address is None:
            # 尝试使用 finder+aob 自动定位
            try:
                if not self.scanner:
                    raise RuntimeError("当前未提供 AdvancedScanner，无法自动定位，请手动输入地址。")
                struct_name = self.struct_selector.currentText()
                base_address = self.structure_manager.find_base_with_aob(self.scanner, struct_name)
                QMessageBox.information(self, "自动定位成功", f"已通过 AOB 自动找到基址: {hex(base_address)}")
            except Exception as e:
                QMessageBox.warning(self, "未找到基址", f"自动定位失败: {e}\n\n请手动输入基址或使用脚本。")
            return

        struct_name = self.struct_selector.currentText()
        if not struct_name or struct_name == "选择结构体":
            QMessageBox.warning(self, "错误", "请选择一个结构体。")
            return

        try:
            struct_instance = self.structure_manager.get_structure(struct_name, base_address)
            self.loaded_structures[struct_name] = struct_instance  # 缓存实例供编辑时使用
            self.table.setRowCount(0)

            # 添加顶层结构体行
            self.add_table_row(struct_name, base_address, struct_name, None)

            # 添加所有成员
            self._add_struct_members_to_table(struct_instance, struct_name)

            self.table.resizeColumnsToContents()

        except (KeyError, ValueError) as e:
            QMessageBox.critical(self, "加载失败", f"无法加载结构体 '{struct_name}':\n{e}")

    def _add_struct_members_to_table(self, struct_instance, parent_name):
        if not hasattr(struct_instance, '_flat_definition') or not isinstance(struct_instance._flat_definition, dict):
            print(f"警告: {parent_name} 不是一个有效的结构体实例或其定义为空。")
            return

        # 对成员按偏移量进行排序，以确保正确的显示顺序
        sorted_members = sorted(struct_instance._flat_definition.items(), key=lambda item: item[1][0])

        for member_path, (offset, member_type) in sorted_members:
            # 我们只添加基本类型的成员到表格中
            if member_type not in self.structure_manager.definitions:
                display_name = f"{parent_name}.{member_path}"
                full_member_path = f"{parent_name}.{member_path}"
                # 这里的地址是相对于顶层结构体基地址的最终地址
                member_address = struct_instance.base_address + offset
                self.add_table_row(display_name, member_address, member_type, struct_instance, full_member_path)

    def add_table_row(self, display_name, address, value_type, parent_instance=None, member_path=None):
        row_position = self.table.rowCount()
        self.table.insertRow(row_position)

        value_str = "N/A"

        # 1) 如果是结构体成员
        if parent_instance and member_path and self.structure_manager and self.structure_manager.pm:
            try:
                value = parent_instance.read_member(member_path)
                if isinstance(value, bytes):
                    value_str = value.hex().upper()
                else:
                    value_str = str(value)
            except Exception as e:
                print(f"读取成员 {display_name} 失败: {e}")
                value_str = "读取错误"
        # 2) 手动单地址行，尝试直接读取
        elif self.structure_manager and self.structure_manager.pm:
            try:
                value = self.structure_manager.read_value(address, value_type)
                if isinstance(value, bytes):
                    value_str = value.hex().upper()
                else:
                    value_str = str(value)
            except Exception:
                pass
        
        name_item = QTableWidgetItem(display_name)
        address_item = QTableWidgetItem(hex(address))
        type_item = QTableWidgetItem(value_type)
        value_item = QTableWidgetItem(value_str)

        if member_path:
            name_item.setData(Qt.ItemDataRole.UserRole, member_path)

        # 顶层结构体行和成员行都不可编辑名称、地址、类型
        name_item.setFlags(name_item.flags() & ~Qt.ItemIsEditable)
        address_item.setFlags(address_item.flags() & ~Qt.ItemIsEditable)
        type_item.setFlags(type_item.flags() & ~Qt.ItemIsEditable)
        # 顶层结构体的值列以及手动行的值默认不可编辑
        if not member_path:
            value_item.setFlags(value_item.flags() & ~Qt.ItemIsEditable)

        self.table.setItem(row_position, 0, name_item)
        self.table.setItem(row_position, 1, address_item)
        self.table.setItem(row_position, 2, type_item)
        self.table.setItem(row_position, 3, value_item)

    def handle_item_change(self, item):
        """处理单元格值变化"""
        # 1. 基本检查
        if self.is_refreshing or item.column() != 3:
            return

        member_item = self.table.item(item.row(), 0)
        if not member_item:
            return

        # 2. 获取元数据
        full_member_path = member_item.data(Qt.ItemDataRole.UserRole)
        # 如果没有 full_member_path，说明是手动添加的地址或顶层结构体行，暂不处理编辑
        if not full_member_path:
            return

        # 从 display_name 解析出 struct_name
        try:
            struct_name, member_path = full_member_path.split('.', 1)
        except ValueError:
            # 路径格式不正确，无法处理
            return

        # 防止因读取错误而触发写入循环
        current_value_text = item.text()
        if current_value_text == "读取错误":
            # 如果用户试图编辑 "读取错误" 状态，可以先恢复之前的值
            previous_value = item.data(Qt.ItemDataRole.UserRole)
            if previous_value is not None:
                item.setText(str(previous_value))
            return

        try:
            # 3. 定位结构体实例
            if struct_name not in self.loaded_structures:
                raise ValueError(f"未找到已加载的结构体 '{struct_name}'")
            struct_instance = self.loaded_structures[struct_name]

            # 4. 写入内存
            new_value_str = item.text()
            struct_instance.write_member(member_path, new_value_str)
            
            # 5. 更新UI反馈
            # 重新读取以确认写入成功
            written_value = struct_instance.read_member(member_path)
            item.setData(Qt.ItemDataRole.UserRole, written_value) # 存储实际值
            
            # 暂时改变背景颜色以示成功
            item.setBackground(QColor(200, 255, 200)) # 绿色
            QTimer.singleShot(1000, lambda: item.setBackground(QColor(Qt.transparent)))

        except Exception as e:
            # 6. 错误处理
            logging.error(f"处理值变化失败: {e}")
            
            # 恢复之前的值，防止无限递归
            previous_value = item.data(Qt.ItemDataRole.UserRole)

            self.is_refreshing = True # 标记正在刷新
            if previous_value is not None:
                item.setText(str(previous_value))
            else:
                item.setText("写入失败") # 如果没有旧值，则显示失败
            self.is_refreshing = False

            # 显示错误弹窗
            QMessageBox.critical(self, "写入失败", f"无法写入成员 '{full_member_path}':\n\n{e}")
            
            # 恢复背景色
            item.setBackground(QColor(Qt.transparent))

    def show_context_menu(self, pos):
        """显示右键菜单"""
        item = self.table.itemAt(pos)
        if not item:
            return

        menu = QMenu()
        
        # 复制选项
        copy_addr = menu.addAction("复制地址")
        copy_value = menu.addAction("复制值")
        menu.addSeparator()
        
        # 编辑选项
        edit_value = menu.addAction("编辑值")
        menu.addSeparator()
        
        # 格式选项
        format_menu = menu.addMenu("显示格式")
        hex_format = format_menu.addAction("十六进制")
        dec_format = format_menu.addAction("十进制")
        
        # 处理菜单动作
        action = menu.exec_(self.table.viewport().mapToGlobal(pos))
        
        if action == copy_addr:
            addr_item = self.table.item(item.row(), 1)
            if addr_item and addr_item.text():
                QApplication.clipboard().setText(addr_item.text())
        
        elif action == copy_value:
            value_item = self.table.item(item.row(), 3)  # 值列
            if value_item:
                QApplication.clipboard().setText(value_item.text())
        
        elif action == edit_value:
            value_item = self.table.item(item.row(), 3)  # 值列
            if value_item:
                value_item.setFlags(value_item.flags() | Qt.ItemIsEditable)
                self.table.editItem(value_item)
        
        elif action == hex_format:
            self.set_value_format(item.row(), "hex")
        
        elif action == dec_format:
            self.set_value_format(item.row(), "dec")

    def set_value_format(self, row, format_type):
        """设置值的显示格式"""
        value_item = self.table.item(row, 3)
        if not value_item:
            return

        try:
            # 获取原始值
            value = value_item.data(Qt.ItemDataRole.UserRole)
            if value is None:
                return
                
            # 根据格式类型显示
            if format_type == "hex":
                if isinstance(value, (int, float)):
                    value_item.setText(hex(int(value)))
            elif format_type == "dec":
                if isinstance(value, (int, float)):
                    value_item.setText(str(value))
        except Exception as e:
            logging.error(f"设置值格式失败: {e}")

    def show_analyze_dialog(self):
        dialog = AnalyzeDialog(self)
        if dialog.exec_():
            address_str = dialog.address_input.text()
            try:
                address = int(address_str, 16)
                struct_name = self.struct_selector.currentText()
                if not struct_name:
                    QMessageBox.warning(self, "错误", "请先选择一个结构体。")
                    return
                # 复用 load_from_struct 的逻辑，但使用用户提供的地址
                self.load_from_struct(base_address=address)
            except ValueError:
                QMessageBox.warning(self, "输入无效", "请输入一个有效的十六进制地址。")

    # ------------------------ 新增: 手动添加地址 ------------------------
    def show_add_address_dialog(self):
        dialog = AddAddressDialog(self)
        if dialog.exec_():
            desc = dialog.desc_input.text().strip() or "UnnamedAddr"
            addr_str = dialog.addr_input.text().strip()
            val_type = dialog.type_combo.currentText().strip() or "int"

            try:
                address = int(addr_str, 16)
            except ValueError:
                QMessageBox.warning(self, "输入无效", "地址必须是十六进制，例如 0x140000000")
                return

            # 手动行 parent_instance=None, member_path=None
            self.add_table_row(desc, address, val_type, None, None)

    def build_structure_from_selection(self):
        """将当前选中行写入 definitions.yaml 并生成 finder(module+offset)。"""
        if not self.structure_manager or not self.structure_manager.pm:
            QMessageBox.warning(self, "错误", "请先附加到一个进程。")
            return

        selected_items = self.table.selectedItems()
        if not selected_items:
            QMessageBox.warning(self, "提示", "请先在表格中选中一行地址。")
            return

        row = selected_items[0].row()
        desc = self.table.item(row, 0).text()
        addr_str = self.table.item(row, 1).text()
        val_type = self.table.item(row, 2).text()

        try:
            address = int(addr_str, 16)
        except ValueError:
            QMessageBox.warning(self, "错误", f"无法解析地址: {addr_str}")
            return

        # 询问结构体名称
        struct_name, ok = QInputDialog.getText(self, "结构体名称", "请输入结构体名称:", text=f"{desc}Struct")
        if not ok or not struct_name:
            return

        field_name = desc.replace(" ", "_") or "Field0"

        # 查找地址所属模块
        module_found = None
        for mod in self.structure_manager.pm.list_modules():
            base = mod.lpBaseOfDll
            size = mod.SizeOfImage
            if base <= address < base + size:
                module_found = mod
                break

        finder_dict = {}
        if module_found:
            # 使用模块偏移
            offset = address - module_found.lpBaseOfDll
            finder_dict = {
                'module': module_found.name,
                'offset': offset
            }
        else:
            # 提示用户选择使用静态地址保存
            reply = QMessageBox.question(
                self, "保存方式",
                "未能确定该地址属于哪个模块，是否按静态地址保存？\n\n" +
                "静态地址适用于程序每次启动地址固定或已由Hook写入，全局唯一。",
                QMessageBox.Yes | QMessageBox.No, QMessageBox.No)

            if reply == QMessageBox.Yes:
                finder_dict = {
                    'address': hex(address)
                }
            else:
                return  # 用户取消

        new_struct_def = {
            struct_name: {
                'finder': finder_dict,
                'members': {
                    field_name: {
                        'offset': 0,
                        'type': val_type
                    }
                }
            }
        }

        # 合并到现有 definitions
        self.structure_manager.definitions.update(new_struct_def)
        try:
            self.structure_manager.save_definitions()
        except Exception as e:
            QMessageBox.warning(self, "写入失败", f"保存 definitions.yaml 时出错:\n{e}")
            return

        self.populate_struct_selector()
        QMessageBox.information(self, "成功", f"已生成结构体 '{struct_name}' 并保存。\n下次可直接下拉选择并点击'从地址分析'加载。")

    def refresh_all(self):
        """刷新地址表中的所有数据"""
        if not self.structure_manager:
            return
            
        try:
            # 保存当前选中的行
            current_row = self.table.currentRow()
            
            # 清空表格
            self.table.setRowCount(0)
            
            # 重新加载所有结构体数据
            if hasattr(self, 'loaded_structures'):
                for struct_name, struct_instance in self.loaded_structures.items():
                    if struct_instance is not None:
                        self.update_structure_values(struct_name, struct_instance)
            
            # 恢复选中的行
            if current_row >= 0 and current_row < self.table.rowCount():
                self.table.setCurrentCell(current_row, 0)
        except Exception as e:
            logging.error(f"刷新地址表失败: {e}")
            raise

    def auto_refresh_values(self):
        """自动刷新值"""
        if not self.structure_manager:
            return
            
        try:
            for row in range(self.table.rowCount()):
                value_item = self.table.item(row, 3)
                if not value_item:
                    continue
                    
                # 跳过正在编辑的单元格
                if self.table.state() == QTableWidget.EditingState and \
                   self.table.currentItem() == value_item:
                    continue
                    
                # 获取结构体信息
                member_item = self.table.item(row, 0)
                if not member_item:
                    continue
                    
                struct_name = member_item.data(Qt.ItemDataRole.UserRole)
                if not struct_name or struct_name not in self.loaded_structures:
                    continue
                    
                struct_instance = self.loaded_structures[struct_name]
                member_name = member_item.text()
                
                # 读取新值
                try:
                    new_value = struct_instance.read_member(member_name)
                    if new_value != value_item.data(Qt.ItemDataRole.UserRole):
                        value_item.setData(Qt.ItemDataRole.UserRole, new_value)
                        value_item.setText(str(new_value))
                        value_item.setBackground(QColor(200, 200, 255))  # 蓝色背景表示更新
                        QTimer.singleShot(500, lambda: value_item.setBackground(QColor(255, 255, 255)))
                except Exception:
                    pass  # 忽略读取错误
        except Exception as e:
            logging.error(f"自动刷新值失败: {e}")

    def update_structure_values(self, struct_name, struct_instance):
        """根据当前结构体实例刷新/填充表格"""
        # 添加顶层行
        self.add_table_row(struct_name, struct_instance._base_address, struct_name, None)
        # 添加成员
        self._add_struct_members_to_table(struct_instance, struct_name)

class AnalyzeDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("从地址分析")
        layout = QFormLayout(self)

        self.address_input = QLineEdit(self)
        self.address_input.setPlaceholderText("例如: 0x140000000")
        layout.addRow("地址 (十六进制):", self.address_input)

        button_box = QHBoxLayout()
        ok_button = QPushButton("确定")
        ok_button.clicked.connect(self.accept)
        cancel_button = QPushButton("取消")
        cancel_button.clicked.connect(self.reject)
        button_box.addStretch(1)
        button_box.addWidget(ok_button)
        button_box.addWidget(cancel_button)

        layout.addRow(button_box)
        self.setLayout(layout)

# ------------------- Dialog for manual address -------------------

class AddAddressDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("添加地址")

        layout = QFormLayout(self)

        self.desc_input = QLineEdit(self)
        self.addr_input = QLineEdit(self)
        # 类型下拉框，提供常见数据类型
        self.type_combo = QComboBox(self)
        self.type_combo.addItems([
            "int", "float", "double", "byte", "short", "long", "bool", "string", "bytes"
        ])

        self.desc_input.setPlaceholderText("示例: DamageMultiplier")
        self.addr_input.setPlaceholderText("如: 0x140000000")

        layout.addRow("描述:", self.desc_input)
        layout.addRow("地址(16进制):", self.addr_input)
        layout.addRow("类型:", self.type_combo)

        btn_layout = QHBoxLayout()
        ok_btn = QPushButton("确定")
        cancel_btn = QPushButton("取消")
        ok_btn.clicked.connect(self.accept)
        cancel_btn.clicked.connect(self.reject)
        btn_layout.addStretch(1)
        btn_layout.addWidget(ok_btn)
        btn_layout.addWidget(cancel_btn)

        layout.addRow(btn_layout)