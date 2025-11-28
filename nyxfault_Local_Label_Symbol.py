from binaryninja import (
    PluginCommand,
    SymbolType,
    log_info
)
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTableWidget, QTableWidgetItem,
    QLineEdit, QLabel, QHeaderView, QPushButton, QApplication
)
from PySide6.QtCore import Qt
from PySide6.QtGui import QFont

# Global reference to keep the window alive
_local_label_symbols_window = None

class LocalLabelSymbolsWindow(QWidget):
    def __init__(self, bv, parent=None):
        super().__init__(parent)
        self.bv = bv
        self.all_symbols = []
        self.init_ui()
        self.load_symbols()
        
    def init_ui(self):
        self.setWindowTitle("Local Label Symbols")
        self.setFixedSize(800, 600)
        
        layout = QVBoxLayout()
        
        # Search bar
        search_layout = QHBoxLayout()
        search_layout.addWidget(QLabel("Search:"))
        
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Search local labels...")
        self.search_input.textChanged.connect(self.filter_symbols)
        search_layout.addWidget(self.search_input)
        
        self.count_label = QLabel("Total: 0")
        search_layout.addWidget(self.count_label)
        
        refresh_btn = QPushButton("Refresh")
        refresh_btn.clicked.connect(self.load_symbols)
        search_layout.addWidget(refresh_btn)
        
        search_layout.addStretch()
        layout.addLayout(search_layout)
        
        # Table
        self.table = QTableWidget()
        self.table.setColumnCount(2)
        self.table.setHorizontalHeaderLabels(["Label Name", "Address"])
        
        # Set table properties
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
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
        
    def load_symbols(self):
        """Load all LocalLabelSymbols from the binary"""
        self.all_symbols = []
        
        # Get all LocalLabelSymbols
        local_label_symbols = self.bv.get_symbols_of_type(SymbolType.LocalLabelSymbol)
        
        for sym in local_label_symbols:
            self.all_symbols.append({
                'name': sym.full_name or "Unknown",
                'address': sym.address,
                'symbol': sym
            })
        
        self.all_symbols.sort(key=lambda x: x['address'])
        self.filter_symbols()
        
    def filter_symbols(self):
        """Filter symbols based on search text"""
        search_text = self.search_input.text().lower()
        
        if search_text:
            filtered_symbols = [
                sym for sym in self.all_symbols 
                if search_text in sym['name'].lower()
            ]
        else:
            filtered_symbols = self.all_symbols
        
        self.populate_table(filtered_symbols)
        
    def populate_table(self, symbols):
        """Populate the table with symbols"""
        self.table.setRowCount(len(symbols))
        
        for row, symbol in enumerate(symbols):
            # Label Name
            name_item = QTableWidgetItem(symbol['name'])
            name_item.setData(Qt.UserRole, symbol['symbol'])
            self.table.setItem(row, 0, name_item)
            
            # Address
            addr_item = QTableWidgetItem(hex(symbol['address']))
            addr_item.setTextAlignment(Qt.AlignRight | Qt.AlignVCenter)
            self.table.setItem(row, 1, addr_item)
        
        self.count_label.setText(f"Total: {len(symbols)}")
        
    def on_double_click(self, index):
        """Handle double-click to navigate to label"""
        row = index.row()
        symbol_item = self.table.item(row, 0)
        
        if symbol_item:
            symbol = symbol_item.data(Qt.UserRole)
            if symbol and symbol.address:
                self.bv.navigate(self.bv.view, symbol.address)
                log_info(f"Navigated to {symbol.full_name} @ {hex(symbol.address)}")
    
    def closeEvent(self, event):
        """Handle window close - clear global reference"""
        global _local_label_symbols_window
        _local_label_symbols_window = None
        event.accept()

def show_local_label_symbols(bv):
    global _local_label_symbols_window
    
    if _local_label_symbols_window is not None:
        _local_label_symbols_window.raise_()
        _local_label_symbols_window.activateWindow()
        return
    
    _local_label_symbols_window = LocalLabelSymbolsWindow(bv)
    _local_label_symbols_window.show()
    _local_label_symbols_window.raise_()
    _local_label_symbols_window.activateWindow()

PluginCommand.register(
    "nyxFault-Binja\\Show Local Label Symbols",
    "Display all LocalLabelSymbols in a searchable table",
    show_local_label_symbols
)