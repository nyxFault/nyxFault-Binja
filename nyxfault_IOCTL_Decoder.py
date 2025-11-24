from binaryninja import PluginCommand
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLineEdit, QLabel, 
    QPushButton, QTextEdit, QApplication, QMessageBox, QGroupBox
)
from PySide6.QtCore import Qt
from PySide6.QtGui import QFont

# Based on work by Satoshi Tanda (https://github.com/tandasat/WinIoCtlDecoder)
# Device types from OSR Online (https://www.osronline.com/article.cfm^article=229.htm)

_ioctl_decoder_window = None

class WinIoCtlDecoderWindow(QWidget):
    def __init__(self, bv, parent=None):
        super().__init__(parent)
        self.bv = bv
        self.init_ui()
        self.center_window()
        
    def init_ui(self):
        self.setWindowTitle("Windows IOCTL Code Decoder")
        self.setFixedSize(600, 500)
        
        layout = QVBoxLayout()
        
        title = QLabel("Windows IOCTL Code Decoder")
        title.setAlignment(Qt.AlignCenter)
        title_font = QFont()
        title_font.setPointSize(16)
        title_font.setBold(True)
        title.setFont(title_font)
        layout.addWidget(title)
        
        input_group = QGroupBox("IOCTL Code Input")
        input_layout = QVBoxLayout()
        
        input_instructions = QLabel(
            "Enter IOCTL code in decimal or hexadecimal format:\n"
            "Examples: 0x220086, 2228358 (decimal)"
        )
        input_instructions.setWordWrap(True)
        input_layout.addWidget(input_instructions)
        
        ioctl_layout = QHBoxLayout()
        ioctl_layout.addWidget(QLabel("IOCTL Code:"))
        
        self.ioctl_input = QLineEdit()
        self.ioctl_input.setPlaceholderText("Enter IOCTL code (e.g., 0x220086)")
        self.ioctl_input.returnPressed.connect(self.decode_ioctl)
        ioctl_layout.addWidget(self.ioctl_input)
        
        decode_btn = QPushButton("Decode")
        decode_btn.clicked.connect(self.decode_ioctl)
        decode_btn.setDefault(True)
        ioctl_layout.addWidget(decode_btn)
        
        input_layout.addLayout(ioctl_layout)
        input_group.setLayout(input_layout)
        layout.addWidget(input_group)
        
        results_group = QGroupBox("Decoded Results")
        results_layout = QVBoxLayout()
        
        self.results_text = QTextEdit()
        self.results_text.setReadOnly(True)
        self.results_text.setMaximumHeight(300)
        
        mono_font = QFont("Courier New", 11)
        self.results_text.setFont(mono_font)
        
        results_layout.addWidget(self.results_text)
        results_group.setLayout(results_layout)
        layout.addWidget(results_group)
        
        button_layout = QHBoxLayout()
        
        clear_btn = QPushButton("Clear")
        clear_btn.clicked.connect(self.clear_all)
        button_layout.addWidget(clear_btn)
        
        button_layout.addStretch()
        
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(self.close)
        button_layout.addWidget(close_btn)
        
        layout.addLayout(button_layout)
        
        self.setLayout(layout)
        
    def center_window(self):
        screen_geometry = QApplication.primaryScreen().availableGeometry()
        x = (screen_geometry.width() - self.width()) // 2
        y = (screen_geometry.height() - self.height()) // 2
        self.move(x, y)
        
    def decode_ioctl(self):
        ioctl_text = self.ioctl_input.text().strip()
        if not ioctl_text:
            QMessageBox.warning(self, "Input Required", "Please enter an IOCTL code to decode.")
            return
            
        try:
            ioctl_text = ioctl_text.replace(' ', '')
            
            if ioctl_text.lower().startswith('0x'):
                ioctl_code = int(ioctl_text, 16)
            else:
                try:
                    ioctl_code = int(ioctl_text)
                except ValueError:
                    ioctl_code = int(ioctl_text, 16)
                    
            result = self.winio_decode(ioctl_code)
            self.results_text.setPlainText(result)
            
        except ValueError:
            QMessageBox.warning(self, "Invalid Input", "Please enter a valid IOCTL code in decimal or hexadecimal format.")
        except Exception as e:
            QMessageBox.critical(self, "Decoding Error", f"Failed to decode IOCTL code:\n{str(e)}")
    
    def winio_decode(self, ioctl_code):
        access_names = [
            "FILE_ANY_ACCESS",
            "FILE_READ_ACCESS", 
            "FILE_WRITE_ACCESS",
            "FILE_READ_ACCESS | FILE_WRITE_ACCESS",
        ]
        
        method_names = [
            "METHOD_BUFFERED",
            "METHOD_IN_DIRECT",
            "METHOD_OUT_DIRECT", 
            "METHOD_NEITHER",
        ]

# Device type mapping from OSR Online
# Source: https://www.osronline.com/article.cfm^article=229.htm

        device_map = {
            0x01: "BEEP",
            0x02: "CD_ROM",
            0x03: "CD_ROM_FILE_SYSTEM",
            0x04: "CONTROLLER", 
            0x05: "DATALINK",
            0x06: "DFS",
            0x07: "DISK",
            0x08: "DISK_FILE_SYSTEM",
            0x09: "FILE_SYSTEM",
            0x0A: "INPORT_PORT",
            0x0B: "KEYBOARD",
            0x0C: "MAILSLOT",
            0x0D: "MIDI_IN",
            0x0E: "MIDI_OUT",
            0x0F: "MOUSE",
            0x10: "MULTI_UNC_PROVIDER",
            0x11: "NAMED_PIPE",
            0x12: "NETWORK",
            0x13: "NETWORK_BROWSER", 
            0x14: "NETWORK_FILE_SYSTEM",
            0x15: "NULL",
            0x16: "PARALLEL_PORT",
            0x17: "PHYSICAL_NETCARD",
            0x18: "PRINTER",
            0x19: "SCANNER",
            0x1A: "SERIAL_MOUSE_PORT",
            0x1B: "SERIAL_PORT",
            0x1C: "SCREEN",
            0x1D: "SOUND",
            0x1E: "STREAMS",
            0x1F: "TAPE",
            0x20: "TAPE_FILE_SYSTEM",
            0x21: "TRANSPORT",
            0x22: "UNKNOWN",
            0x23: "VIDEO",
            0x24: "VIRTUAL_DISK",
            0x25: "WAVE_IN",
            0x26: "WAVE_OUT",
            0x27: "8042_PORT",
            0x28: "NETWORK_REDIRECTOR",
            0x29: "BATTERY",
            0x2A: "BUS_EXTENDER",
            0x2B: "MODEM",
            0x2C: "VDM",
            0x2D: "MASS_STORAGE",
            0x2E: "SMB",
            0x2F: "KS",
            0x30: "CHANGER",
            0x31: "SMARTCARD",
            0x32: "ACPI",
            0x33: "DVD",
            0x34: "FULLSCREEN_VIDEO", 
            0x35: "DFS_FILE_SYSTEM",
            0x36: "DFS_VOLUME"
        }

        device_type_full = (ioctl_code >> 16) & 0xFFFF
        is_custom_device = (device_type_full & 0x8000) != 0
        device_type = device_type_full & 0x7FFF
        
        access = (ioctl_code >> 14) & 0x3
        function_code = (ioctl_code >> 2) & 0xFFF
        method = ioctl_code & 0x3

        device_name = device_map.get(device_type, f"UNKNOWN (0x{device_type:04X})")
        
        if is_custom_device:
            device_name = f"{device_name} [CUSTOM]"

        result_lines = []
        result_lines.append(f"IOCTL Code: 0x{ioctl_code:08X} ({ioctl_code} decimal)")
        result_lines.append("=" * 50)
        result_lines.append(f"Device   : {device_name} (0x{device_type:02X})")
        result_lines.append(f"Function : 0x{function_code:03X}")
        result_lines.append(f"Method   : {method_names[method]} ({method})")
        result_lines.append(f"Access   : {access_names[access]} ({access})")
        
        return "\n".join(result_lines)
    
    def clear_all(self):
        self.ioctl_input.clear()
        self.results_text.clear()
    
    def closeEvent(self, event):
        global _ioctl_decoder_window
        _ioctl_decoder_window = None
        event.accept()

def show_ioctl_decoder(bv):
    global _ioctl_decoder_window
    
    if _ioctl_decoder_window is not None:
        _ioctl_decoder_window.raise_()
        _ioctl_decoder_window.activateWindow()
        return
    
    _ioctl_decoder_window = WinIoCtlDecoderWindow(bv)
    _ioctl_decoder_window.show()
    _ioctl_decoder_window.raise_()
    _ioctl_decoder_window.activateWindow()

PluginCommand.register(
    "nyxFault-Binja\\Windows IOCTL Decoder",
    "Decode Windows Device I/O control codes",
    show_ioctl_decoder
)