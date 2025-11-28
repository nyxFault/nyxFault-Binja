from binaryninja import (
    PluginCommand,
    log_info
)
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTableWidget, QTableWidgetItem,
    QLineEdit, QLabel, QHeaderView, QPushButton, QApplication
)
from PySide6.QtCore import Qt
from PySide6.QtGui import QFont

# Global reference to keep the window alive
_sections_window = None

class SectionsWindow(QWidget):
    def __init__(self, bv, parent=None):
        super().__init__(parent)
        self.bv = bv
        self.all_sections = []
        self.init_ui()
        self.load_sections()
        
    def init_ui(self):
        self.setWindowTitle("Binary Sections")
        self.setFixedSize(900, 600)
        
        layout = QVBoxLayout()
        
        # Search bar
        search_layout = QHBoxLayout()
        search_layout.addWidget(QLabel("Search:"))
        
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Search sections...")
        self.search_input.textChanged.connect(self.filter_sections)
        search_layout.addWidget(self.search_input)
        
        self.count_label = QLabel("Total: 0")
        search_layout.addWidget(self.count_label)
        
        refresh_btn = QPushButton("Refresh")
        refresh_btn.clicked.connect(self.load_sections)
        search_layout.addWidget(refresh_btn)
        
        search_layout.addStretch()
        layout.addLayout(search_layout)
        
        # Table
        self.table = QTableWidget()
        self.table.setColumnCount(5)
        self.table.setHorizontalHeaderLabels([
            "Section Name", 
            "Start Address", 
            "End Address", 
            "Length", 
            "Readable/Executable/Writable"
        ])
        
        # Set table properties
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.Stretch)  # Name column stretches
        header.setSectionResizeMode(1, QHeaderView.ResizeToContents)  # Start
        header.setSectionResizeMode(2, QHeaderView.ResizeToContents)  # End
        header.setSectionResizeMode(3, QHeaderView.ResizeToContents)  # Length
        header.setSectionResizeMode(4, QHeaderView.ResizeToContents)  # Permissions
        
        self.table.setSortingEnabled(True)
        self.table.doubleClicked.connect(self.on_double_click)
        
        layout.addWidget(self.table)
        self.setLayout(layout)
        self.center_window()
        
    def center_window(self):
        """Center the window on the screen"""
        screen_geometry = QApplication.primaryScreen().availableGeometry()
        x = (screen_geometry.width() - self.width()) // 2
        y = (screen_geometry.height() - self.height()) // 2
        self.move(x, y)
        
    def load_sections(self):
        """Load all sections from the binary"""
        self.all_sections = []
        
        # Get all sections
        for section in self.bv.sections.values():
            # Get section permissions
            readable = self.bv.is_offset_readable(section.start)
            executable = self.bv.is_offset_executable(section.start)
            writable = self.bv.is_offset_writable(section.start)
            
            permissions = f"{'R' if readable else '-'}{'X' if executable else '-'}{'W' if writable else '-'}"
            
            self.all_sections.append({
                'name': section.name,
                'start': section.start,
                'end': section.end,
                'length': section.end - section.start,
                'permissions': permissions,
                'section': section
            })
        
        self.all_sections.sort(key=lambda x: x['start'])
        self.filter_sections()
        
    def filter_sections(self):
        """Filter sections based on search text"""
        search_text = self.search_input.text().lower()
        
        if search_text:
            filtered_sections = [
                section for section in self.all_sections 
                if search_text in section['name'].lower()
            ]
        else:
            filtered_sections = self.all_sections
        
        self.populate_table(filtered_sections)
        
    def populate_table(self, sections):
        """Populate the table with sections"""
        self.table.setRowCount(len(sections))
        
        for row, section_data in enumerate(sections):
            # Section Name
            name_item = QTableWidgetItem(section_data['name'])
            name_item.setData(Qt.UserRole, section_data['section'])
            self.table.setItem(row, 0, name_item)
            
            # Start Address
            start_item = QTableWidgetItem(hex(section_data['start']))
            start_item.setTextAlignment(Qt.AlignRight | Qt.AlignVCenter)
            self.table.setItem(row, 1, start_item)
            
            # End Address
            end_item = QTableWidgetItem(hex(section_data['end']))
            end_item.setTextAlignment(Qt.AlignRight | Qt.AlignVCenter)
            self.table.setItem(row, 2, end_item)
            
            # Length
            length_item = QTableWidgetItem(hex(section_data['length']))
            length_item.setTextAlignment(Qt.AlignRight | Qt.AlignVCenter)
            self.table.setItem(row, 3, length_item)
            
            # Permissions
            perm_item = QTableWidgetItem(section_data['permissions'])
            perm_item.setTextAlignment(Qt.AlignCenter)
            self.table.setItem(row, 4, perm_item)
        
        self.count_label.setText(f"Total: {len(sections)}")
        
    def on_double_click(self, index):
        """Handle double-click to navigate to section start"""
        row = index.row()
        section_item = self.table.item(row, 0)
        
        if section_item:
            section = section_item.data(Qt.UserRole)
            if section and section.start:
                self.bv.navigate(self.bv.view, section.start)
                log_info(f"Navigated to section '{section.name}' @ {hex(section.start)}")
    
    def closeEvent(self, event):
        """Handle window close - clear global reference"""
        global _sections_window
        _sections_window = None
        event.accept()

def show_sections(bv):
    global _sections_window
    
    if _sections_window is not None:
        _sections_window.raise_()
        _sections_window.activateWindow()
        return
    
    _sections_window = SectionsWindow(bv)
    _sections_window.show()
    _sections_window.raise_()
    _sections_window.activateWindow()

PluginCommand.register(
    "nyxFault-Binja\\Show Sections",
    "Display all binary sections in a searchable table",
    show_sections
)