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
_segments_window = None

class SegmentsWindow(QWidget):
    def __init__(self, bv, parent=None):
        super().__init__(parent)
        self.bv = bv
        self.all_segments = []
        self.init_ui()
        self.load_segments()
        
    def init_ui(self):
        self.setWindowTitle("Binary Segments")
        self.setFixedSize(900, 600)
        
        layout = QVBoxLayout()
        
        # Search bar
        search_layout = QHBoxLayout()
        search_layout.addWidget(QLabel("Search:"))
        
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Search by address range...")
        self.search_input.textChanged.connect(self.filter_segments)
        search_layout.addWidget(self.search_input)
        
        self.count_label = QLabel("Total: 0")
        search_layout.addWidget(self.count_label)
        
        refresh_btn = QPushButton("Refresh")
        refresh_btn.clicked.connect(self.load_segments)
        search_layout.addWidget(refresh_btn)
        
        search_layout.addStretch()
        layout.addLayout(search_layout)
        
        # Table
        self.table = QTableWidget()
        self.table.setColumnCount(5)
        self.table.setHorizontalHeaderLabels([
            "Start Address", 
            "End Address", 
            "Length", 
            "Readable/Executable/Writable",
            "Data Length"
        ])
        
        # Set table properties for full border
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.Stretch)  # Start - stretches
        header.setSectionResizeMode(1, QHeaderView.Stretch)  # End - stretches
        header.setSectionResizeMode(2, QHeaderView.ResizeToContents)  # Length
        header.setSectionResizeMode(3, QHeaderView.ResizeToContents)  # Permissions
        header.setSectionResizeMode(4, QHeaderView.ResizeToContents)  # Data Length
        
        # Enable grid lines for full borders
        self.table.setShowGrid(True)
        self.table.setGridStyle(Qt.SolidLine)
        
        # Set selection behavior and style
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setAlternatingRowColors(True)
        
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
        
    def load_segments(self):
        """Load all segments from the binary"""
        self.all_segments = []
        
        # Get all segments
        for segment in self.bv.segments:
            permissions = f"{'R' if segment.readable else '-'}{'X' if segment.executable else '-'}{'W' if segment.writable else '-'}"
            
            self.all_segments.append({
                'start': segment.start,
                'end': segment.end,
                'length': segment.length,
                'data_length': segment.data_length,
                'permissions': permissions,
                'segment': segment
            })
        
        self.all_segments.sort(key=lambda x: x['start'])
        self.filter_segments()
        
    def filter_segments(self):
        """Filter segments based on search text"""
        search_text = self.search_input.text().lower()
        
        if search_text:
            filtered_segments = [
                segment for segment in self.all_segments 
                if search_text in hex(segment['start']) or 
                   search_text in hex(segment['end']) or
                   search_text in hex(segment['length'])
            ]
        else:
            filtered_segments = self.all_segments
        
        self.populate_table(filtered_segments)
        
    def populate_table(self, segments):
        """Populate the table with segments"""
        self.table.setRowCount(len(segments))
        
        for row, segment_data in enumerate(segments):
            # Start Address
            start_item = QTableWidgetItem(hex(segment_data['start']))
            start_item.setTextAlignment(Qt.AlignRight | Qt.AlignVCenter)
            start_item.setData(Qt.UserRole, segment_data['segment'])
            self.table.setItem(row, 0, start_item)
            
            # End Address
            end_item = QTableWidgetItem(hex(segment_data['end']))
            end_item.setTextAlignment(Qt.AlignRight | Qt.AlignVCenter)
            self.table.setItem(row, 1, end_item)
            
            # Length
            length_item = QTableWidgetItem(hex(segment_data['length']))
            length_item.setTextAlignment(Qt.AlignRight | Qt.AlignVCenter)
            self.table.setItem(row, 2, length_item)
            
            # Permissions
            perm_item = QTableWidgetItem(segment_data['permissions'])
            perm_item.setTextAlignment(Qt.AlignCenter)
            self.table.setItem(row, 3, perm_item)
            
            # Data Length
            data_length_item = QTableWidgetItem(hex(segment_data['data_length']))
            data_length_item.setTextAlignment(Qt.AlignCenter)
            self.table.setItem(row, 4, data_length_item)
        
        self.count_label.setText(f"Total: {len(segments)}")
        
        # Ensure the table fills the available space
        self.table.horizontalHeader().setStretchLastSection(True)
        
    def on_double_click(self, index):
        """Handle double-click to navigate to segment start"""
        row = index.row()
        segment_item = self.table.item(row, 0)
        
        if segment_item:
            segment = segment_item.data(Qt.UserRole)
            if segment and segment.start:
                self.bv.navigate(self.bv.view, segment.start)
                log_info(f"Navigated to segment @ {hex(segment.start)}")
    
    def closeEvent(self, event):
        """Handle window close - clear global reference"""
        global _segments_window
        _segments_window = None
        event.accept()

def show_segments(bv):
    global _segments_window
    
    if _segments_window is not None:
        _segments_window.raise_()
        _segments_window.activateWindow()
        return
    
    _segments_window = SegmentsWindow(bv)
    _segments_window.show()
    _segments_window.raise_()
    _segments_window.activateWindow()

PluginCommand.register(
    "nyxFault-Binja\\Show Segments",
    "Display all binary segments in a searchable table",
    show_segments
)