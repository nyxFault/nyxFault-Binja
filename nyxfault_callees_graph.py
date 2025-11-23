from binaryninja import (
    PluginCommand, 
    get_text_line_input, 
    show_message_box, 
    MessageBoxButtonSet, 
    MessageBoxIcon,
    enums,
    log_info
)

from binaryninja.enums import MediumLevelILOperation
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QApplication, QGraphicsView, QGraphicsScene, QGraphicsItem, QGraphicsEllipseItem, QGraphicsTextItem, QGraphicsLineItem, QFrame
)
from PySide6.QtCore import Qt, QPointF
from PySide6.QtGui import QFont, QColor, QPen, QBrush, QPainter
import math

# Global references to keep windows alive
_callees_graph_window = None

class DraggableNodeItem(QGraphicsEllipseItem):
    def __init__(self, x, y, radius, node_id, color, text, address=None):
        super().__init__(-radius, -radius, radius * 2, radius * 2)
        self.setPos(x, y)
        self.node_id = node_id
        self.color = color
        self.text = text
        self.address = address
        self.radius = radius
        
        # Make draggable
        self.setFlag(QGraphicsItem.ItemIsMovable, True)
        self.setFlag(QGraphicsItem.ItemIsSelectable, True)
        self.setFlag(QGraphicsItem.ItemSendsGeometryChanges, True)
        
        # Styling - use brighter colors
        self.setBrush(QBrush(color.lighter(130)))  
        self.setPen(QPen(QColor(0, 0, 0), 2))
        
    def itemChange(self, change, value):
        if change == QGraphicsItem.ItemPositionHasChanged:
            scene = self.scene()
            if scene and hasattr(scene, 'update_edges_for_node'):
                scene.update_edges_for_node(self.node_id, self.pos())
        return super().itemChange(change, value)

class CalleesGraphScene(QGraphicsScene):
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

class CalleesGraphWindow(QWidget):
    def __init__(self, bv, source_function, callees_data, parent=None):
        super().__init__(parent)
        self.bv = bv
        self.source_function = source_function
        self.callees_data = callees_data  # List of (callee_name, callee_addr, callsite_addr)
        self.init_ui()
        self.center_window()
        
    def init_ui(self):
        self.setWindowTitle(f"Callees Graph: {self.source_function}")
        self.setMinimumSize(800, 600)
        
        layout = QVBoxLayout()
        
        # Title
        title = QLabel(f"Callees from: {self.source_function}")
        title.setAlignment(Qt.AlignCenter)
        title_font = QFont()
        title_font.setPointSize(16)
        title_font.setBold(True)
        title.setFont(title_font)
        layout.addWidget(title)
        
        # Info label
        info_label = QLabel(f"Found {len(self.callees_data)} callee(s) - Double-click any node to navigate to address")
        info_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(info_label)
        
        # Graph visualization
        graph_frame = QFrame()
        graph_frame.setFrameStyle(QFrame.Box)
        graph_frame.setLineWidth(2)
        graph_layout = QVBoxLayout()
        
        self.scene = CalleesGraphScene(self.bv)
        self.view = QGraphicsView(self.scene)
        self.view.setRenderHint(QPainter.Antialiasing)
        
        # Create the graph visualization
        self.create_callees_graph()
        
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
        
    def create_callees_graph(self):
        """Create a visual representation of the callees graph"""
        self.scene.clear()
        
        node_radius = 50
        horizontal_spacing = 200
        vertical_spacing = 150
        
        # Colors for nodes
        source_color = QColor(135, 206, 250)  # Brighter Light Blue for target
        callee_colors = [
            QColor(144, 238, 144),  # Light Green 
            QColor(255, 192, 203),  # Brighter Light Pink
            QColor(255, 255, 102),  # Brighter Light Yellow
            QColor(221, 160, 221),  # Brighter Light Purple
            QColor(255, 218, 185),  # Light Peach
            QColor(173, 216, 230),  # Light Blue
            QColor(152, 251, 152),  # Pale Green (brighter)
        ]
        
        # Calculate positions - source in center, callees around it
        center_x = 400
        center_y = 300
        
        # Create source node (center) - use function start address
        source_address = None
        source_funcs = self.bv.get_functions_by_name(self.source_function)
        if source_funcs:
            source_address = source_funcs[0].start
        
        source_node = DraggableNodeItem(center_x, center_y, node_radius, 0, source_color, 
                                       self.source_function, source_address)
        self.scene.addItem(source_node)
        self.scene.node_items[0] = source_node
        
        # Create source text
        source_text = QGraphicsTextItem(f"Source:\n{self.source_function}")
        source_text.setDefaultTextColor(QColor(0, 0, 0))
        source_text.setParentItem(source_node)
        bold_font = QFont()
        bold_font.setBold(True)
        source_text.setFont(bold_font)
        text_rect = source_text.boundingRect()
        source_text.setPos(-text_rect.width() / 2, -text_rect.height() / 2)
        self.scene.addItem(source_text)
        
        # Create callee nodes in a circle around the source
        num_callees = len(self.callees_data)
        for i, (callee_name, callee_addr, callsite_addr) in enumerate(self.callees_data):
            angle = 2 * math.pi * i / num_callees
            radius = 300  # Distance from center
            
            x = center_x + radius * math.cos(angle)
            y = center_y + radius * math.sin(angle)
            
            # Create callee node - prefer callee_addr for navigation, fallback to callsite_addr
            navigation_addr = callee_addr if callee_addr else callsite_addr
            color = callee_colors[i % len(callee_colors)]
            
            # Create display text
            display_name = callee_name if callee_name else "unknown"
            if len(display_name) > 20:  # Truncate long names
                display_name = display_name[:17] + "..."
            
            callee_node = DraggableNodeItem(x, y, node_radius, i + 1, color, 
                                           display_name, navigation_addr)
            self.scene.addItem(callee_node)
            self.scene.node_items[i + 1] = callee_node
            
            # Create callee text
            callee_text_lines = [display_name]
            if callee_addr:
                callee_text_lines.append(f"@ {hex(callee_addr)}")
            else:
                callee_text_lines.append(f"called @ {hex(callsite_addr)}")
            
            callee_text = QGraphicsTextItem("\n".join(callee_text_lines))
            callee_text.setDefaultTextColor(QColor(0, 0, 0))
            callee_text.setParentItem(callee_node)
            
            # Make text bold
            bold_font = QFont()
            bold_font.setBold(True)
            callee_text.setFont(bold_font)

            text_rect = callee_text.boundingRect()
            callee_text.setPos(-text_rect.width() / 2, -text_rect.height() / 2)
            self.scene.addItem(callee_text)
            
            # Create edge from source to callee
            self.create_edge(0, i + 1, QColor(70, 130, 180))  # Steel Blue
        
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
        self.create_callees_graph()
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
        global _callees_graph_window
        _callees_graph_window = None
        event.accept()

def show_callees_graph_pyqt(bv):
    """PyQt version of the callees graph plugin"""
    global _callees_graph_window
    
    # Get function name from user
    fn_name = get_text_line_input("Enter function name (e.g., main):", "Callees Flowgraph")
    if not fn_name:
        return
    if isinstance(fn_name, bytes):
        fn_name = fn_name.decode()

    funcs = bv.get_functions_by_name(fn_name.strip())
    if not funcs:
        show_message_box(
            "Not Found",
            f"No function named '{fn_name.strip()}' was found.",
            MessageBoxButtonSet.OKButtonSet,
            MessageBoxIcon.ErrorIcon
        )
        return
    func = funcs[0]

    if not func.mlil:
        show_message_box(
            "No MLIL",
            f"No MLIL is available for function '{func.name}'.",
            MessageBoxButtonSet.OKButtonSet,
            MessageBoxIcon.InformationIcon
        )
        return

    callees = set()
    
    for block in func.mlil.basic_blocks:
        for il in block:
            if il.operation in [MediumLevelILOperation.MLIL_CALL, MediumLevelILOperation.MLIL_CALL_SSA]:
                callee_name = None
                callee_addr = None
                callsite_addr = il.address
                
                # Method 1: Try to get the callee function directly
                if hasattr(il, 'dest') and hasattr(il.dest, 'value'):
                    # Check if this is a constant value (direct call)
                    if hasattr(il.dest.value, 'value'):
                        target_addr = il.dest.value.value
                        target_func = bv.get_function_at(target_addr)
                        if target_func:
                            callee_name = target_func.name
                            callee_addr = target_addr
                
                # Method 2: Check for imported functions via tokens
                if not callee_name and hasattr(il.dest, 'tokens'):
                    tokens = il.dest.tokens
                    if tokens:
                        # Try to extract function name from tokens
                        name_str = "".join([t.text for t in tokens if t.text.strip()])
                        if name_str:
                            # Check if this matches any known imports
                            for sym in bv.get_symbols_of_type(enums.SymbolType.ImportedFunctionSymbol):
                                if sym.name == name_str or sym.short_name == name_str or sym.full_name == name_str:
                                    callee_name = sym.name
                                    callee_addr = sym.address
                                    break
                            if not callee_name:
                                callee_name = name_str
                
                # Method 3: Use possible_call_targets as fallback
                if not callee_name and hasattr(il, "possible_call_targets") and il.possible_call_targets:
                    for target in il.possible_call_targets:
                        target_func = bv.get_function_at(target)
                        if target_func:
                            callee_name = target_func.name
                            callee_addr = target
                            break
                        else:
                            # Check imports
                            sym = bv.get_symbol_at(target)
                            if sym and sym.type in [enums.SymbolType.ImportedFunctionSymbol, 
                                                   enums.SymbolType.FunctionSymbol]:
                                callee_name = sym.name
                                callee_addr = target
                                break
                
                # Method 4: Final fallback - string representation
                if not callee_name:
                    try:
                        callee_name = str(il.dest)
                    except Exception:
                        callee_name = "unknown"
                
                # Clean up the name for display
                if callee_name:
                    callee_name = callee_name.strip("'\"")
                    
                callees.add((callee_name, callee_addr, callsite_addr))

    if not callees:
        show_message_box(
            "No Callees",
            f"No callees found for function '{func.name}'.",
            MessageBoxButtonSet.OKButtonSet,
            MessageBoxIcon.InformationIcon
        )
        return

    # Prepare callees data for the graph
    callees_data = list(callees)
    
    # Close existing viewer if open
    if _callees_graph_window is not None:
        _callees_graph_window.close()
    
    # Create and show the callees graph window
    _callees_graph_window = CalleesGraphWindow(bv, func.name, callees_data)
    _callees_graph_window.show()
    _callees_graph_window.raise_()
    _callees_graph_window.activateWindow()

PluginCommand.register(
    "nyxFault-Binja\\Callees Flowgraph (PyQt)",
    "Draw a PyQt flowgraph of all callees from a specified function (with imports & callsites).",
    show_callees_graph_pyqt
)