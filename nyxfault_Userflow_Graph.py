from binaryninja import PluginCommand
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QSpinBox, QTextEdit, QMessageBox, QApplication, QGroupBox, QGraphicsView, QGraphicsScene, QGraphicsItem, QGraphicsEllipseItem, QGraphicsTextItem, QGraphicsLineItem, QFrame
)
from PySide6.QtCore import Qt, QPointF
from PySide6.QtGui import QFont, QColor, QPen, QBrush, QPainter
import math

# Global references to keep windows alive
_flow_graph_builder_window = None
_flow_graph_viewer_window = None

class DraggableNodeItem(QGraphicsEllipseItem):
    def __init__(self, x, y, radius, node_id, color, text):
        super().__init__(-radius, -radius, radius * 2, radius * 2)
        self.setPos(x, y)
        self.node_id = node_id
        self.color = color
        self.text = text
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

class FlowGraphScene(QGraphicsScene):
    def __init__(self):
        super().__init__()
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

class FlowGraphViewerWindow(QWidget):
    def __init__(self, nodes, edges, parent=None):
        super().__init__(parent)
        self.nodes = nodes
        self.edges = edges
        self.init_ui()
        self.center_window()
        
    def init_ui(self):
        self.setWindowTitle("Flow Graph Viewer - Detached")
        self.setMinimumSize(800, 600)
        
        layout = QVBoxLayout()
        
        # Title
        title = QLabel("Custom Flow Graph")
        title.setAlignment(Qt.AlignCenter)
        title_font = QFont()
        title_font.setPointSize(16)
        title_font.setBold(True)
        title.setFont(title_font)
        layout.addWidget(title)
        
        # Graph visualization
        graph_frame = QFrame()
        graph_frame.setFrameStyle(QFrame.Box)
        graph_frame.setLineWidth(2)
        graph_layout = QVBoxLayout()
        
        self.scene = FlowGraphScene()
        self.view = QGraphicsView(self.scene)
        self.view.setRenderHint(QPainter.Antialiasing)
        
        # Create the graph visualization
        self.create_graph_visualization()
        
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
        
    def create_graph_visualization(self):
        """Create a visual representation of the flow graph with top-to-bottom layout"""
        self.scene.clear()
        
        node_radius = 40
        horizontal_spacing = 150
        vertical_spacing = 120
        
        # Colors for nodes 
        node_colors = [
            QColor(173, 216, 230),  # Light Blue
            QColor(144, 238, 144),  # Light Green
            QColor(255, 182, 193),  # Light Pink
            QColor(255, 255, 153),  # Light Yellow
            QColor(216, 191, 216),  # Light Purple
            QColor(255, 218, 185),  # Light Peach
        ]
        
        # Calculate node positions in a VERTICAL layout (top to bottom)
        nodes_per_column = max(1, (len(self.nodes) + 2) // 3)  # Better column calculation
        node_positions = []

        for i, node in enumerate(self.nodes):
            row = i // nodes_per_column  # Changed from % to //
            col = i % nodes_per_column   # Changed from // to %
            x = col * horizontal_spacing + 100
            y = row * vertical_spacing + 100
            node_positions.append(QPointF(x, y))
            
            # Create draggable node
            color = node_colors[i % len(node_colors)]
            node_item = DraggableNodeItem(x, y, node_radius, i, color, f"Node {i}")
            self.scene.addItem(node_item)
            self.scene.node_items[i] = node_item
            
            # Create node text - FIXED: Position text relative to node center
            text = QGraphicsTextItem(f"Node {i}")
            text.setDefaultTextColor(QColor(0, 0, 0))
            
            # Center the text on the node by setting it as a child and positioning relative to node center
            text.setParentItem(node_item)
            
            # Position text at the center of the node (node is at 0,0 in local coordinates)
            text_rect = text.boundingRect()
            text.setPos(-text_rect.width() / 2, -text_rect.height() / 2)
        
        # Create edges
        for src_idx, dst_idx in self.edges:
            if src_idx < len(node_positions) and dst_idx < len(node_positions):
                start_pos = node_positions[src_idx]
                end_pos = node_positions[dst_idx]
                
                # Create arrow line
                line = QGraphicsLineItem(start_pos.x(), start_pos.y(), end_pos.x(), end_pos.y())
                line.setPen(QPen(QColor(70, 130, 180), 2))  # Steel Blue
                self.scene.addItem(line)
                
                # Add arrow head
                arrow1, arrow2 = self.add_arrow_head(start_pos, end_pos)
                
                # Store edge information for updates
                self.scene.edge_items.append((src_idx, dst_idx, line, arrow1, arrow2))
        
        # Set scene rect to fit all items
        self.scene.setSceneRect(self.scene.itemsBoundingRect())
        
    def add_arrow_head(self, start_pos, end_pos):
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
        
        # For arrow heads
        arrow_line1.setPen(QPen(QColor(70, 130, 180), 2))  # Steel Blue
        arrow_line2.setPen(QPen(QColor(70, 130, 180), 2))  # Steel Blue
        
        self.scene.addItem(arrow_line1)
        self.scene.addItem(arrow_line2)
        
        return arrow_line1, arrow_line2
    
    def relayout_graph(self):
        """Re-layout the graph with top-to-bottom organization"""
        self.create_graph_visualization()
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
        global _flow_graph_viewer_window
        _flow_graph_viewer_window = None
        event.accept()

class FlowGraphBuilderWindow(QWidget):
    def __init__(self, bv, parent=None):
        super().__init__(parent)
        self.bv = bv
        self.init_ui()
        self.center_window()
        
    def init_ui(self):
        self.setWindowTitle("Flow Graph Builder")
        self.setFixedSize(500, 600)
        
        layout = QVBoxLayout()
        
        # Title
        title = QLabel("Flow Graph Builder")
        title.setAlignment(Qt.AlignCenter)
        title_font = QFont()
        title_font.setPointSize(16)
        title_font.setBold(True)
        title.setFont(title_font)
        layout.addWidget(title)
        
        # Node Configuration Group
        node_group = QGroupBox("Node Configuration")
        node_layout = QVBoxLayout()
        
        node_input_layout = QHBoxLayout()
        node_input_layout.addWidget(QLabel("Number of Nodes:"))
        self.node_count_input = QSpinBox()
        self.node_count_input.setRange(1, 50)
        self.node_count_input.setValue(5)
        self.node_count_input.setToolTip("Number of nodes in the flow graph (1-50)")
        node_input_layout.addWidget(self.node_count_input)
        node_input_layout.addStretch()
        node_layout.addLayout(node_input_layout)
        
        node_group.setLayout(node_layout)
        layout.addWidget(node_group)
        
        # Edge Configuration Group
        edge_group = QGroupBox("Edge Configuration")
        edge_layout = QVBoxLayout()
        
        edge_instructions = QLabel(
            "Enter edge connections (one per line):\n"
            "Format: source_node target_node\n"
            "Example:\n"
            "0 1\n"
            "0 2\n" 
            "1 3\n"
            "2 3"
        )
        edge_instructions.setWordWrap(True)
        edge_layout.addWidget(edge_instructions)
        
        self.edge_input = QTextEdit()
        self.edge_input.setPlaceholderText("Enter edges here...\nExample:\n0 1\n0 2\n1 3")
        self.edge_input.setMaximumHeight(150)
        edge_layout.addWidget(self.edge_input)
        
        edge_group.setLayout(edge_layout)
        layout.addWidget(edge_group)
        
        # Preview Group
        preview_group = QGroupBox("Preview")
        preview_layout = QVBoxLayout()
        
        self.preview_text = QTextEdit()
        self.preview_text.setReadOnly(True)
        self.preview_text.setMaximumHeight(150)
        preview_layout.addWidget(self.preview_text)
        
        preview_group.setLayout(preview_layout)
        layout.addWidget(preview_group)
        
        # Buttons
        button_layout = QHBoxLayout()
        
        preview_btn = QPushButton("Update Preview")
        preview_btn.clicked.connect(self.update_preview)
        preview_btn.setToolTip("Update the preview with current configuration")
        button_layout.addWidget(preview_btn)
        
        generate_btn = QPushButton("Generate Flow Graph")
        generate_btn.clicked.connect(self.generate_flow_graph)
        generate_btn.setDefault(True)
        generate_btn.setToolTip("Generate and display the flow graph in detached window")
        button_layout.addWidget(generate_btn)
        
        clear_btn = QPushButton("Clear All")
        clear_btn.clicked.connect(self.clear_all)
        clear_btn.setToolTip("Clear all inputs and preview")
        button_layout.addWidget(clear_btn)
        
        layout.addLayout(button_layout)
        
        # Status
        self.status_label = QLabel("Ready to build flow graph")
        self.status_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.status_label)
        
        self.setLayout(layout)
        
        # Set font for edge input and preview
        mono_font = QFont("Courier New", 10)
        self.edge_input.setFont(mono_font)
        self.preview_text.setFont(mono_font)
        
    def center_window(self):
        """Center the window on the screen"""
        screen_geometry = QApplication.primaryScreen().availableGeometry()
        x = (screen_geometry.width() - self.width()) // 2
        y = (screen_geometry.height() - self.height()) // 2
        self.move(x, y)
        
    def update_preview(self):
        """Update the preview based on current inputs"""
        try:
            num_nodes = self.node_count_input.value()
            edges_text = self.edge_input.toPlainText().strip()
            
            preview_lines = [f"Flow Graph Preview", f"{'='*20}"]
            preview_lines.append(f"Nodes: {num_nodes}")
            preview_lines.append("")
            preview_lines.append("Edges:")
            
            if edges_text:
                edges = []
                valid_edges = 0
                for line_num, line in enumerate(edges_text.split('\n'), 1):
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        parts = line.split()
                        if len(parts) != 2:
                            preview_lines.append(f"  Line {line_num}: INVALID - Expected 2 numbers, got {len(parts)}")
                            continue
                            
                        src, dst = map(int, parts)
                        if 0 <= src < num_nodes and 0 <= dst < num_nodes:
                            edges.append((src, dst))
                            preview_lines.append(f"  {src} → {dst}")
                            valid_edges += 1
                        else:
                            preview_lines.append(f"  Line {line_num}: INVALID - Node indices must be 0-{num_nodes-1}")
                    except ValueError:
                        preview_lines.append(f"  Line {line_num}: INVALID - Non-numeric values")
                
                preview_lines.append("")
                preview_lines.append(f"Valid edges: {valid_edges}")
                preview_lines.append(f"Total connections: {len(edges)}")
            else:
                preview_lines.append("  No edges defined")
                
            self.preview_text.setPlainText('\n'.join(preview_lines))
            self.status_label.setText("Preview updated successfully")
            
        except Exception as e:
            self.status_label.setText(f"Error updating preview: {str(e)}")
            
    def generate_flow_graph(self):
        """Generate and display the flow graph in detached window"""
        try:
            num_nodes = self.node_count_input.value()
            edges_text = self.edge_input.toPlainText().strip()
            
            # Parse edges
            edges = []
            invalid_edges = []
            
            if edges_text:
                for line_num, line in enumerate(edges_text.split('\n'), 1):
                    line = line.strip()
                    if not line:
                        continue
                    
                    try:
                        src, dst = map(int, line.split())
                        if 0 <= src < num_nodes and 0 <= dst < num_nodes:
                            edges.append((src, dst))
                        else:
                            invalid_edges.append(f"Line {line_num}: Node indices {src},{dst} out of range (0-{num_nodes-1})")
                    except ValueError:
                        invalid_edges.append(f"Line {line_num}: Invalid format '{line}'")
            
            # Create nodes list for visualization
            nodes = [f"Node {i}" for i in range(num_nodes)]
            
            # Show the graph in detached window
            self.show_detached_flow_graph(nodes, edges, invalid_edges)
                
        except Exception as e:
            self.status_label.setText(f"Error generating flow graph")
            QMessageBox.critical(self, "Error", f"Failed to generate flow graph:\n{str(e)}")
            
    def show_detached_flow_graph(self, nodes, edges, invalid_edges):
        """Show the flow graph in a detached PyQt window"""
        global _flow_graph_viewer_window
        
        # Close existing viewer if open
        if _flow_graph_viewer_window is not None:
            _flow_graph_viewer_window.close()
        
        # Create new viewer window
        _flow_graph_viewer_window = FlowGraphViewerWindow(nodes, edges)
        _flow_graph_viewer_window.show()
        _flow_graph_viewer_window.raise_()
        _flow_graph_viewer_window.activateWindow()
        
        # Show summary
        if invalid_edges:
            summary = f"Generated graph with {len(nodes)} nodes and {len(edges)} edges.\n\nInvalid edges:\n" + "\n".join(invalid_edges)
            QMessageBox.warning(self, "Flow Graph Generated with Warnings", summary)
        else:
            self.status_label.setText(f"Success! Generated {len(nodes)} nodes with {len(edges)} edges")
            
    def clear_all(self):
        """Clear all inputs and preview"""
        self.node_count_input.setValue(5)
        self.edge_input.clear()
        self.preview_text.clear()
        self.status_label.setText("All inputs cleared")
        
    def closeEvent(self, event):
        """Handle window close - clear global reference"""
        global _flow_graph_builder_window
        _flow_graph_builder_window = None
        event.accept()

def launch_user_flow_graph(bv):
    global _flow_graph_builder_window
    
    # If window already exists, bring it to front
    if _flow_graph_builder_window is not None:
        _flow_graph_builder_window.raise_()
        _flow_graph_builder_window.activateWindow()
        return
    
    # Create new window
    _flow_graph_builder_window = FlowGraphBuilderWindow(bv)
    _flow_graph_builder_window.show()
    _flow_graph_builder_window.raise_()
    _flow_graph_builder_window.activateWindow()

PluginCommand.register(
    "nyxFault-Binja\\User Flow Graph Builder",
    "Build and visualize custom flow graphs in detached PyQt windows",
    launch_user_flow_graph
)