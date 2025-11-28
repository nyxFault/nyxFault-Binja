from binaryninja import (
    PluginCommand, 
    get_text_line_input, 
    show_message_box, 
    MessageBoxButtonSet, 
    MessageBoxIcon,
    log_info
)

from binaryninja.enums import  MediumLevelILOperation
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QApplication, QGraphicsView, QGraphicsScene, QGraphicsItem, QGraphicsEllipseItem,
    QGraphicsTextItem, QGraphicsLineItem, QFrame
)
from PySide6.QtCore import Qt, QPointF
from PySide6.QtGui import QFont, QColor, QPen, QBrush, QPainter
import math

# Global references to keep windows alive
_callers_graph_window = None

class DraggableNodeItem(QGraphicsEllipseItem):
    def __init__(self, x, y, radius, node_id, color, text, address=None):
        super().__init__(-radius, -radius, radius * 2, radius * 2)
        self.setPos(x, y)
        self.node_id = node_id
        self.color = color
        self.text = text
        self.address = address  # Store address for navigation
        self.radius = radius
        
        # Make draggable
        self.setFlag(QGraphicsItem.ItemIsMovable, True)
        self.setFlag(QGraphicsItem.ItemIsSelectable, True)
        self.setFlag(QGraphicsItem.ItemSendsGeometryChanges, True)
        
        # Styling
        self.setBrush(QBrush(color.lighter(150)))
        self.setPen(QPen(QColor(0, 0, 0), 2))
        
    def itemChange(self, change, value):
        if change == QGraphicsItem.ItemPositionHasChanged:
            # Update connected edges when node moves
            scene = self.scene()
            if scene and hasattr(scene, 'update_edges_for_node'):
                scene.update_edges_for_node(self.node_id, self.pos())
        return super().itemChange(change, value)

class CallersGraphScene(QGraphicsScene):
    def __init__(self, bv):
        super().__init__()
        self.bv = bv
        self.node_items = {}
        self.edge_items = []
        
    def update_edges_for_node(self, node_id, new_pos):
        """Update all edges connected to this node"""
        for edge_info in self.edge_items:
            src_id, dst_id, line_item, arrow1, arrow2 = edge_info
            if src_id == node_id or dst_id == node_id:
                self.update_edge_position(src_id, dst_id, line_item, arrow1, arrow2)
                
    def update_edge_position(self, src_id, dst_id, line_item, arrow1, arrow2):
        """Update the position of an edge between two nodes"""
        if src_id in self.node_items and dst_id in self.node_items:
            src_pos = self.node_items[src_id].pos()
            dst_pos = self.node_items[dst_id].pos()
            
            # Update main line
            line_item.setLine(src_pos.x(), src_pos.y(), dst_pos.x(), dst_pos.y())
            
            # Update arrow heads
            self.update_arrow_head(src_pos, dst_pos, arrow1, arrow2)

    def update_arrow_head(self, start_pos, end_pos, arrow1, arrow2):
        """Update arrow head position"""
        arrow_size = 10
        
        # Calculate angle
        dx = end_pos.x() - start_pos.x()
        dy = end_pos.y() - start_pos.y()
        angle = math.atan2(dy, dx)
        
        # Arrow head points
        arrow_p1 = QPointF(
            end_pos.x() - arrow_size * math.cos(angle - math.pi / 6),
            end_pos.y() - arrow_size * math.sin(angle - math.pi / 6)
        )
        arrow_p2 = QPointF(
            end_pos.x() - arrow_size * math.cos(angle + math.pi / 6),
            end_pos.y() - arrow_size * math.sin(angle + math.pi / 6)
        )
        
        # Update arrow head lines
        arrow1.setLine(end_pos.x(), end_pos.y(), arrow_p1.x(), arrow_p1.y())
        arrow2.setLine(end_pos.x(), end_pos.y(), arrow_p2.x(), arrow_p2.y())
    
    def mouseDoubleClickEvent(self, event):
        """Handle double-click events on nodes"""
        items = self.items(event.scenePos())
        for item in items:
            if isinstance(item, DraggableNodeItem) and item.address is not None:
                # Navigate to the address in Binary Ninja
                self.bv.navigate(self.bv.view, item.address)
                log_info(f"Navigated to address: {hex(item.address)}")
                break
        super().mouseDoubleClickEvent(event)

class CallersGraphWindow(QWidget):
    def __init__(self, bv, target_function, callers_data, parent=None):
        super().__init__(parent)
        self.bv = bv
        self.target_function = target_function
        self.callers_data = callers_data  # List of (function_name, callsite_addr, function_obj)
        self.init_ui()
        self.center_window()
        
    def init_ui(self):
        self.setWindowTitle(f"Callers Graph: {self.target_function}")
        self.setMinimumSize(800, 600)
        
        layout = QVBoxLayout()
        
        # Title
        title = QLabel(f"Callers of: {self.target_function}")
        title.setAlignment(Qt.AlignCenter)
        title_font = QFont()
        title_font.setPointSize(16)
        title_font.setBold(True)
        title.setFont(title_font)
        layout.addWidget(title)
        
        # Info label
        info_label = QLabel(f"Found {len(self.callers_data)} caller(s) - Double-click any node to navigate to address")
        info_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(info_label)
        
        # Graph visualization
        graph_frame = QFrame()
        graph_frame.setFrameStyle(QFrame.Box)
        graph_frame.setLineWidth(2)
        graph_layout = QVBoxLayout()
        
        self.scene = CallersGraphScene(self.bv)
        self.view = QGraphicsView(self.scene)
        self.view.setRenderHint(QPainter.Antialiasing)
        
        # Create the graph visualization
        self.create_callers_graph()
        
        graph_layout.addWidget(self.view)
        graph_frame.setLayout(graph_layout)
        layout.addWidget(graph_frame)
        
        # Controls
        controls_layout = QHBoxLayout()
        
        zoom_in_btn = QPushButton("Zoom In")
        zoom_in_btn.clicked.connect(self.zoom_in)
        controls_layout.addWidget(zoom_in_btn)
        
        zoom_out_btn = QPushButton("Zoom Out")
        zoom_out_btn.clicked.connect(self.zoom_out)
        controls_layout.addWidget(zoom_out_btn)
        
        reset_view_btn = QPushButton("Reset View")
        reset_view_btn.clicked.connect(self.reset_view)
        controls_layout.addWidget(reset_view_btn)
        
        layout_btn = QPushButton("Re-layout")
        layout_btn.clicked.connect(self.relayout_graph)
        controls_layout.addWidget(layout_btn)
        
        controls_layout.addStretch()
        
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(self.close)
        controls_layout.addWidget(close_btn)
        
        layout.addLayout(controls_layout)
        
        self.setLayout(layout)
        
    def create_callers_graph(self):
        """Create a visual representation of the callers graph"""
        self.scene.clear()
        
        node_radius = 50
        horizontal_spacing = 200
        vertical_spacing = 150
        
        # Colors for nodes
        target_color = QColor(135, 206, 250)  # Brighter Light Blue for target
        caller_colors = [
            QColor(144, 238, 144),  # Light Green (already bright)
            QColor(255, 192, 203),  # Brighter Light Pink
            QColor(255, 255, 102),  # Brighter Light Yellow
            QColor(221, 160, 221),  # Brighter Light Purple
            QColor(255, 218, 185),  # Light Peach
            QColor(173, 216, 230),  # Light Blue
            QColor(152, 251, 152),  # Pale Green (brighter)
        ]
        
        # Calculate positions - target in center, callers around it
        center_x = 400
        center_y = 300
        
        # Create target node (center) - for target function, use its start address
        target_address = None
        # Try to find the target function to get its address
        target_funcs = self.bv.get_functions_by_name(self.target_function)
        if target_funcs:
            target_address = target_funcs[0].start
        
        target_node = DraggableNodeItem(center_x, center_y, node_radius, 0, target_color, 
                                       self.target_function, target_address)
        self.scene.addItem(target_node)
        self.scene.node_items[0] = target_node
        
        # Create target text
        target_text = QGraphicsTextItem(f"Target:\n{self.target_function}")
        target_text.setDefaultTextColor(QColor(0, 0, 0))
        # Make text bold
        bold_font = QFont()
        bold_font.setBold(True)
        target_text.setFont(bold_font)

        target_text.setParentItem(target_node)
        text_rect = target_text.boundingRect()
        target_text.setPos(-text_rect.width() / 2, -text_rect.height() / 2)
        self.scene.addItem(target_text)
        
        # Create caller nodes in a circle around the target
        num_callers = len(self.callers_data)
        for i, (caller_name, callsite_addr, func_obj) in enumerate(self.callers_data):
            angle = 2 * math.pi * i / num_callers
            radius = 300  # Distance from center
            
            x = center_x + radius * math.cos(angle)
            y = center_y + radius * math.sin(angle)
            
            # Create caller node - use callsite address for navigation
            color = caller_colors[i % len(caller_colors)]
            caller_node = DraggableNodeItem(x, y, node_radius, i + 1, color, 
                                           caller_name, callsite_addr)
            self.scene.addItem(caller_node)
            self.scene.node_items[i + 1] = caller_node
            
            # Create caller text
            caller_text = QGraphicsTextItem(f"{caller_name}\n@{hex(callsite_addr)}")
            caller_text.setDefaultTextColor(QColor(0, 0, 0))
            # Make text bold
            bold_font = QFont()
            bold_font.setBold(True)
            caller_text.setFont(bold_font)
            caller_text.setParentItem(caller_node)
            text_rect = caller_text.boundingRect()
            caller_text.setPos(-text_rect.width() / 2, -text_rect.height() / 2)
            self.scene.addItem(caller_text)
            
            # Create edge from caller to target
            self.create_edge(i + 1, 0, QColor(70, 130, 180))  # Steel Blue
        
        # Set scene rect to fit all items
        self.scene.setSceneRect(self.scene.itemsBoundingRect())
        
    def create_edge(self, src_id, dst_id, color):
        """Create an edge between two nodes"""
        if src_id in self.scene.node_items and dst_id in self.scene.node_items:
            src_pos = self.scene.node_items[src_id].pos()
            dst_pos = self.scene.node_items[dst_id].pos()
            
            # Create arrow line
            line = QGraphicsLineItem(src_pos.x(), src_pos.y(), dst_pos.x(), dst_pos.y())
            line.setPen(QPen(color, 2))
            self.scene.addItem(line)
            
            # Add arrow head
            arrow1, arrow2 = self.add_arrow_head(src_pos, dst_pos, color)
            
            # Store edge information for updates
            self.scene.edge_items.append((src_id, dst_id, line, arrow1, arrow2))
    
    def add_arrow_head(self, start_pos, end_pos, color):
        """Add arrow head to the edge and return the arrow items"""
        arrow_size = 10
        
        # Calculate angle
        dx = end_pos.x() - start_pos.x()
        dy = end_pos.y() - start_pos.y()
        angle = math.atan2(dy, dx)
        
        # Arrow head points
        arrow_p1 = QPointF(
            end_pos.x() - arrow_size * math.cos(angle - math.pi / 6),
            end_pos.y() - arrow_size * math.sin(angle - math.pi / 6)
        )
        arrow_p2 = QPointF(
            end_pos.x() - arrow_size * math.cos(angle + math.pi / 6),
            end_pos.y() - arrow_size * math.sin(angle + math.pi / 6)
        )
        
        # Create arrow head lines
        arrow_line1 = QGraphicsLineItem(end_pos.x(), end_pos.y(), arrow_p1.x(), arrow_p1.y())
        arrow_line2 = QGraphicsLineItem(end_pos.x(), end_pos.y(), arrow_p2.x(), arrow_p2.y())
        
        arrow_line1.setPen(QPen(color, 2))
        arrow_line2.setPen(QPen(color, 2))
        
        self.scene.addItem(arrow_line1)
        self.scene.addItem(arrow_line2)
        
        return arrow_line1, arrow_line2
    
    def relayout_graph(self):
        """Re-layout the graph with circular organization"""
        self.create_callers_graph()
        self.reset_view()
    
    def zoom_in(self):
        self.view.scale(1.2, 1.2)
    
    def zoom_out(self):
        self.view.scale(0.8, 0.8)
    
    def reset_view(self):
        self.view.resetTransform()
        self.view.fitInView(self.scene.itemsBoundingRect(), Qt.KeepAspectRatio)
    
    def center_window(self):
        """Center the window on the screen"""
        screen_geometry = QApplication.primaryScreen().availableGeometry()
        x = (screen_geometry.width() - self.width()) // 2
        y = (screen_geometry.height() - self.height()) // 2
        self.move(x, y)
    
    def closeEvent(self, event):
        """Handle window close - clear global reference"""
        global _callers_graph_window
        _callers_graph_window = None
        event.accept()

def show_callers_graph_pyqt(bv):
    """PyQt version of the callers graph plugin"""
    global _callers_graph_window
    
    # Get function name from user
    fn_name = get_text_line_input("Enter function name (e.g., main):", "Callers Flowgraph")
    if not fn_name:
        return
    if isinstance(fn_name, bytes):
        fn_name = fn_name.decode()

    fn_name = fn_name.strip()
    
    # First, try to find the function by name (defined functions)
    funcs = bv.get_functions_by_name(fn_name)
    
    callers_data = []  # List of (function_name, callsite_addr, function_obj)
    target_name = fn_name
    
    # If not found, try to find it as an imported function
    if not funcs:
        # Search for calls to functions that match our target name
        callers_found = {}
        
        for func in bv.functions:
            if not func.mlil:
                continue
                
            for block in func.mlil.basic_blocks:
                for il in block:
                    if il.operation in [MediumLevelILOperation.MLIL_CALL, MediumLevelILOperation.MLIL_CALL_SSA]:
                        callee_name = None
                        
                        # Method 1: Check if this is a call to an imported function by name
                        if hasattr(il.dest, 'tokens'):
                            tokens = il.dest.tokens
                            if tokens:
                                name_str = "".join([t.text for t in tokens if t.text.strip()])
                                if name_str and fn_name.lower() in name_str.lower():
                                    callee_name = name_str
                        
                        # Method 2: Check the destination address for symbols
                        if not callee_name and hasattr(il.dest, 'value'):
                            if hasattr(il.dest.value, 'value'):
                                dest_addr = il.dest.value.value
                                sym = bv.get_symbol_at(dest_addr)
                                if sym and sym.name and fn_name.lower() in sym.name.lower():
                                    callee_name = sym.name
                        
                        # Method 3: Check possible call targets
                        if not callee_name and hasattr(il, "possible_call_targets"):
                            for target in il.possible_call_targets:
                                sym = bv.get_symbol_at(target)
                                if sym and sym.name and fn_name.lower() in sym.name.lower():
                                    callee_name = sym.name
                                    break
                        
                        if callee_name:
                            # Found a call to our target function
                            if callee_name not in callers_found:
                                callers_found[callee_name] = []
                            callers_found[callee_name].append((func, il.address))
        
        if callers_found:
            # Let the user choose which one if there are multiple
            if len(callers_found) == 1:
                target_name = list(callers_found.keys())[0]
            else:
                target_name = list(callers_found.keys())[0]
                log_info(f"Multiple matches found: {list(callers_found.keys())}. Using: {target_name}")
            
            # Prepare callers data
            callers_list = callers_found[target_name]
            for caller_func, callsite_addr in callers_list:
                callers_data.append((caller_func.name, callsite_addr, caller_func))
        else:
            # No callers found through MLIL analysis
            show_message_box(
                "Not Found",
                f"No calls to function '{fn_name}' found in the binary.\n\n"
                f"This could mean:\n"
                f"1. The function is not called anywhere\n"
                f"2. The function name is different in the import table\n"
                f"3. The analysis hasn't resolved the import references yet",
                MessageBoxButtonSet.OKButtonSet,
                MessageBoxIcon.InformationIcon
            )
            return
    
    else:
        # If we found a regular function (not imported)
        func = funcs[0]
        target_name = func.name
        callers = bv.get_callers(func.start)
        
        if not callers:
            show_message_box(
                "No Callers",
                f"No callers found for function '{func.name}'.",
                MessageBoxButtonSet.OKButtonSet,
                MessageBoxIcon.InformationIcon
            )
            return
        
        # Prepare callers data
        for caller_ref in callers:
            caller_func = caller_ref.function
            callsite_addr = caller_ref.address
            if caller_func is not None:
                callers_data.append((caller_func.name, callsite_addr, caller_func))
    
    # Close existing viewer if open
    if _callers_graph_window is not None:
        _callers_graph_window.close()
    
    # Create and show the callers graph window
    _callers_graph_window = CallersGraphWindow(bv, target_name, callers_data)
    _callers_graph_window.show()
    _callers_graph_window.raise_()
    _callers_graph_window.activateWindow()

PluginCommand.register(
    "nyxFault-Binja\\Callers Flowgraph (PyQt)", 
    "Draw a PyQt flowgraph of all callers of a specified function (including imported functions).",
    show_callers_graph_pyqt
)