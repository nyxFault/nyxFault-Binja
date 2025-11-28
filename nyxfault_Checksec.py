from binaryninja import PluginCommand, log_error
from PySide6.QtWidgets import QWidget, QVBoxLayout, QTextEdit, QPushButton, QApplication
from PySide6.QtCore import Qt
from PySide6.QtGui import QFont
import subprocess
import tempfile
import os

_checksec_window = None

class ChecksecWindow(QWidget):
    def __init__(self, bv, parent=None):
        super().__init__(parent)
        self.bv = bv
        self.setAttribute(Qt.WA_DeleteOnClose, False)
        self.init_ui()
        self.run_checksec()
        
    def init_ui(self):
        self.setWindowTitle("Checksec Output")
        self.setFixedSize(700, 500)
        
        layout = QVBoxLayout()
        
        self.output_text = QTextEdit()
        self.output_text.setReadOnly(True)
        self.output_text.setPlaceholderText("Running checksec...")
        
        refresh_btn = QPushButton("Refresh")
        refresh_btn.clicked.connect(self.run_checksec)
        
        layout.addWidget(self.output_text)
        layout.addWidget(refresh_btn)
        self.setLayout(layout)
        self.center_window()
        
    def center_window(self):
        screen_geometry = QApplication.primaryScreen().availableGeometry()
        x = (screen_geometry.width() - self.width()) // 2
        y = (screen_geometry.height() - self.height()) // 2
        self.move(x, y)
        
    def run_checksec(self):
        self.output_text.setText("Running checksec...")
        try:
            # Save to temporary file
            with tempfile.NamedTemporaryFile(delete=False, suffix=os.path.basename(self.bv.file.filename)) as tmp_file:
                data = self.bv.file.raw.read(0, self.bv.file.raw.end)
                tmp_file.write(data)
                tmp_path = tmp_file.name
            
            # Run checksec
            result = subprocess.run(
                ['pwn', 'checksec', tmp_path],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            output = f"Command: pwn checksec {tmp_path}\n\n"
            if result.stderr:  # checksec outputs to stderr
                output += result.stderr
            if result.stdout:
                output += result.stdout
            if result.returncode != 0:
                output += f"Return code: {result.returncode}"
                
            self.output_text.setText(output)
            os.unlink(tmp_path)
                
        except FileNotFoundError:
            self.output_text.setText("ERROR: 'pwn' command not found. Install pwntools: pip install pwntools")
        except Exception as e:
            self.output_text.setText(f"ERROR: {str(e)}")

def show_checksec(bv):
    global _checksec_window
    if _checksec_window is not None:
        _checksec_window.close()
    _checksec_window = ChecksecWindow(bv)
    _checksec_window.show()

PluginCommand.register(
    "nyxFault-Binja\\Show Checksec",
    "Show checksec output",
    show_checksec
)