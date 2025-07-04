from PyQt5.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QListWidget, QPushButton, QMessageBox, QLineEdit, QFormLayout, QDialog, QTableWidget, QTableWidgetItem, QHeaderView, QComboBox, QInputDialog, QLabel
from PyQt5.QtCore import Qt
import logging

class StructureEditorTab(QWidget):
    def __init__(self, structure_manager, address_table, parent=None):
        super().__init__(parent)
        self.structure_manager = structure_manager
        self.address_table = address_table
        self.init_ui()

    def init_ui(self):
        main_layout = QHBoxLayout(self)

        # 左侧：结构体列表
        left_layout = QVBoxLayout()
        self.struct_list = QListWidget()
        self.struct_list.currentItemChanged.connect(self.on_struct_selected)
        left_layout.addWidget(self.struct_list)

        button_layout = QHBoxLayout()
        self.add_struct_button = QPushButton("添加")
        self.add_struct_button.clicked.connect(self.add_struct)
        self.remove_struct_button = QPushButton("删除")
        self.remove_struct_button.clicked.connect(self.remove_struct)
        button_layout.addWidget(self.add_struct_button)
        button_layout.addWidget(self.remove_struct_button)
        left_layout.addLayout(button_layout)

        # 右侧：成员编辑器
        right_layout = QVBoxLayout()

        # 新增：挂载/卸-载/状态区域
        control_layout = QHBoxLayout()
        self.mount_button = QPushButton("挂载")
        self.mount_button.clicked.connect(self.mount_structure)
        self.unmount_button = QPushButton("卸载")
        self.unmount_button.clicked.connect(self.unmount_structure)
        self.mount_status_label = QLabel("状态: 未挂载")
        self.base_address_label = QLabel("基地址:")
        self.base_address_value = QLineEdit("N/A")
        self.base_address_value.setReadOnly(True)

        control_layout.addWidget(self.mount_button)
        control_layout.addWidget(self.unmount_button)
        control_layout.addStretch(1)
        control_layout.addWidget(self.mount_status_label)
        control_layout.addWidget(self.base_address_label)
        control_layout.addWidget(self.base_address_value)
        right_layout.addLayout(control_layout)

        self.members_table = QTableWidget()
        self.members_table.setColumnCount(3)
        self.members_table.setHorizontalHeaderLabels(["名称", "类型", "偏移量 (Hex)"])
        header = self.members_table.horizontalHeader()
        if header:
            header.setSectionResizeMode(QHeaderView.Stretch)
        right_layout.addWidget(self.members_table)

        member_button_layout = QHBoxLayout()
        self.add_member_button = QPushButton("添加成员")
        self.add_member_button.clicked.connect(self.add_member)
        self.remove_member_button = QPushButton("删除成员")
        self.remove_member_button.clicked.connect(self.remove_member)
        self.save_changes_button = QPushButton("保存更改")
        self.save_changes_button.clicked.connect(self.save_changes)
        member_button_layout.addStretch(1)
        member_button_layout.addWidget(self.add_member_button)
        member_button_layout.addWidget(self.remove_member_button)
        member_button_layout.addWidget(self.save_changes_button)
        right_layout.addLayout(member_button_layout)

        main_layout.addLayout(left_layout, 1)
        main_layout.addLayout(right_layout, 3)

        self.setLayout(main_layout)
        self.load_structs_list()

    def set_structure_manager(self, manager):
        self.structure_manager = manager
        self.load_structs_list()

    def load_structs_list(self):
        self.struct_list.clear()
        if self.structure_manager and self.structure_manager.definitions:
            self.struct_list.addItems(self.structure_manager.definitions.keys())

    def on_struct_selected(self, current, previous):
        if not current:
            self.members_table.setRowCount(0)
            self.mount_status_label.setText("状态: 未选择")
            self.base_address_value.setText("N/A")
            self.mount_button.setEnabled(False)
            self.unmount_button.setEnabled(False)
            return

        struct_name = current.text()
        definition = self.structure_manager.get_definition(struct_name) or {}
        member_dict = definition.get('members', {})
        
        self.mount_button.setEnabled(True)
        self.unmount_button.setEnabled(True)
        
        # 更新挂载状态
        instance = self.structure_manager.get(struct_name)
        if instance:
            self.mount_status_label.setText("状态: <font color='green'>已挂载</font>")
            self.base_address_value.setText(hex(instance.base_address))
            self.mount_button.setEnabled(False)
            self.unmount_button.setEnabled(True)
        else:
            self.mount_status_label.setText("状态: <font color='red'>未挂载</font>")
            self.base_address_value.setText("N/A")
            self.mount_button.setEnabled(True)
            self.unmount_button.setEnabled(False)
        
        self.members_table.setRowCount(0)
        for name, member_def in member_dict.items():
            self.add_member_row(name, member_def.get('type', ''), hex(member_def.get('offset', 0)))

    def add_struct(self):
        if not self.structure_manager:
            QMessageBox.warning(self, '警告', '请先附加到一个进程。')
            return

        struct_name, ok = QInputDialog.getText(self, '添加结构体', '请输入结构体名称:')
        if ok and struct_name:
            if self.structure_manager.get_definition(struct_name):
                QMessageBox.warning(self, '警告', '该结构体名称已存在。')
                return
            self.structure_manager.add_definition(struct_name)
            # 立即保存到 YAML
            try:
                self.structure_manager.save_definitions()
            except Exception as e:
                logging.error(f"保存 definitions.yaml 失败: {e}")
            self.load_structs_list()
            self.struct_list.setCurrentRow(self.struct_list.count() - 1)

    def mount_structure(self):
        if not self.structure_manager:
            QMessageBox.warning(self, '警告', '请先附加到一个进程。')
            return
            
        current_item = self.struct_list.currentItem()
        if not current_item:
            QMessageBox.warning(self, '警告', '请先选择一个要挂载的结构体。')
            return
            
        struct_name = current_item.text()
        try:
            self.structure_manager.mount(struct_name)
            QMessageBox.information(self, '成功', f'结构体 "{struct_name}" 已成功挂载。')
            # 刷新UI并更新地址表
            instance = self.structure_manager.get(struct_name)
            self.on_struct_selected(self.struct_list.currentItem(), None)
            if instance and self.address_table:
                self.address_table.display_mounted_structure(struct_name, instance)
        except Exception as e:
            QMessageBox.critical(self, '挂载失败', f'挂载结构体 "{struct_name}" 失败: {e}\n\n请检查 definitions.yaml 中的 entry_point 是否正确，以及游戏版本是否匹配。')
            logging.error(f"挂载失败: {e}", exc_info=True)
            
    def unmount_structure(self):
        if not self.structure_manager:
            QMessageBox.warning(self, '警告', '请先附加到一个进程。')
            return

        current_item = self.struct_list.currentItem()
        if not current_item:
            QMessageBox.warning(self, '警告', '请先选择一个要卸载的结构体。')
            return

        struct_name = current_item.text()
        try:
            self.structure_manager.unmount(struct_name)
            QMessageBox.information(self, '成功', f'结构体 "{struct_name}" 已成功卸载。')
            # 刷新UI并更新地址表
            self.on_struct_selected(self.struct_list.currentItem(), None) 
            if self.address_table:
                self.address_table.clear_structure_display(struct_name)
        except Exception as e:
            QMessageBox.critical(self, '卸载失败', f'卸载结构体 "{struct_name}" 失败: {e}')
            logging.error(f"卸载失败: {e}", exc_info=True)

    def remove_struct(self):
        if not self.structure_manager:
            QMessageBox.warning(self, '警告', '请先附加到一个进程。')
            return

        current_item = self.struct_list.currentItem()
        if not current_item:
            QMessageBox.warning(self, '警告', '请先选择一个要删除的结构体。')
            return

        struct_name = current_item.text()
        reply = QMessageBox.question(self, '确认删除', f'确定要删除结构体 "{struct_name}" 吗？', QMessageBox.Yes | QMessageBox.No, QMessageBox.No)

        if reply == QMessageBox.Yes:
            self.structure_manager.remove_definition(struct_name)
            # 立即保存到 YAML
            try:
                self.structure_manager.save_definitions()
            except Exception as e:
                logging.error(f"保存 definitions.yaml 失败: {e}")
            self.load_structs_list()

    def add_member(self):
        current_struct_item = self.struct_list.currentItem()
        if not current_struct_item:
            QMessageBox.warning(self, '警告', '请先选择一个结构体。')
            return
        self.add_member_row()

    def remove_member(self):
        current_row = self.members_table.currentRow()
        if current_row >= 0:
            self.members_table.removeRow(current_row)
            # 自动保存修改
            self.save_changes()
        else:
            QMessageBox.warning(self, '警告', '请先选择一个要删除的成员。')

    def save_changes(self):
        if not self.structure_manager:
            QMessageBox.warning(self, '警告', '请先附加到一个进程。')
            return

        current_struct_item = self.struct_list.currentItem()
        if not current_struct_item:
            QMessageBox.warning(self, '警告', '没有选择要保存的结构体。')
            return

        struct_name = current_struct_item.text()
        new_members = {}
        for row in range(self.members_table.rowCount()):
            try:
                name_item = self.members_table.item(row, 0)
                type_item = self.members_table.item(row, 1)
                offset_item = self.members_table.item(row, 2)

                if not (name_item and type_item and offset_item and 
                        name_item.text() and type_item.text() and offset_item.text()):
                    QMessageBox.warning(self, '错误', f'行 {row+1}: 名称、类型和偏移量不能为空。')
                    return
                
                name = name_item.text()
                type = type_item.text()
                offset_str = offset_item.text()

                offset = int(offset_str, 16)
                new_members[name] = {'type': type, 'offset': offset}
            except ValueError:
                QMessageBox.warning(self, '错误', f'行 {row+1}: 偏移量必须是一个有效的十六进制数。')
                return
            except Exception as e:
                QMessageBox.warning(self, '错误', f'处理行 {row+1} 时出错: {e}')
                return

        # 保留 finder 或其他元数据，合并更新
        old_def = self.structure_manager.get_definition(struct_name) or {}
        merged_def = dict(old_def)  # 浅拷贝即可，成员将被替换
        merged_def['members'] = new_members
        self.structure_manager.update_definition(struct_name, merged_def)
        self.structure_manager.save_definitions()
        QMessageBox.information(self, '成功', f'结构体 "{struct_name}" 已保存。')

    def add_member_row(self, name="", type="", offset=""):
        row_pos = self.members_table.rowCount()
        self.members_table.insertRow(row_pos)
        self.members_table.setItem(row_pos, 0, QTableWidgetItem(name))
        self.members_table.setItem(row_pos, 1, QTableWidgetItem(type))
        self.members_table.setItem(row_pos, 2, QTableWidgetItem(offset))

    def refresh(self):
        """刷新结构体编辑器的状态"""
        if not self.structure_manager:
            return
            
        try:
            # 保存当前选中的结构体
            current_struct = self.struct_combo.currentText()
            
            # 重新加载结构体列表
            self.struct_combo.clear()
            if hasattr(self.structure_manager, 'definitions'):
                self.struct_combo.addItems(sorted(self.structure_manager.definitions.keys()))
            
            # 恢复选中的结构体
            if current_struct:
                index = self.struct_combo.findText(current_struct)
                if index >= 0:
                    self.struct_combo.setCurrentIndex(index)
                    self.load_structure(current_struct)
        except Exception as e:
            logging.error(f"刷新结构体编辑器失败: {e}")
            raise