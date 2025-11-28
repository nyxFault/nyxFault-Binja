from binaryninja import (
    PluginCommand, 
    get_text_line_input, 
    show_message_box, 
    MessageBoxButtonSet, 
    MessageBoxIcon,
    log_info,
    BackgroundTaskThread
)

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, 
    QApplication, QTextEdit, QLineEdit, QSpinBox, QProgressBar,
    QGroupBox, QFormLayout, QCheckBox, QDialog
)
from PySide6.QtCore import Qt, QTimer
import traceback

# Global reference to keep the dialog alive
_angr_dialog = None

# Try to import angr, but don't fail if not available
ANGR_AVAILABLE = False
try:
    import angr
    import claripy
    ANGR_AVAILABLE = True
    log_info("angr successfully imported")
except ImportError as e:
    log_info(f"angr not available: {e}")

class AngrSolverTask(BackgroundTaskThread):
    def __init__(self, bv, target_string, avoid_string, input_size, use_argv=True):
        super().__init__("Solving with angr...", True)
        self.bv = bv
        self.target_string = target_string
        self.avoid_string = avoid_string
        self.input_size = input_size
        self.use_argv = use_argv
        self.result = None
        self.error = None
        self._progress_text = "Starting..."
        self._finished = False
        
    def run(self):
        if not ANGR_AVAILABLE:
            self.error = "angr is not installed in Binary Ninja's Python environment"
            self._finished = True
            return
            
        try:
            # Get the binary file path
            binary_path = self.bv.file.original_filename
            log_info(f"Starting angr analysis on: {binary_path}")
            
            # Load the binary
            project = angr.Project(binary_path, auto_load_libs=False)
            
            # Create symbolic input
            if self.use_argv:
                # Symbolic command line argument
                user_input = claripy.BVS('user_input', self.input_size * 8)
                
                # Create state with symbolic argv[1]
                initial_state = project.factory.full_init_state(
                    args=[binary_path, user_input],
                    add_options={
                        angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
                        angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS,
                    }
                )
            else:
                # For stdin input (alternative approach)
                user_input = claripy.BVS('stdin_input', self.input_size * 8)
                initial_state = project.factory.entry_state(
                    stdin=user_input,
                    add_options={
                        angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
                        angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS,
                    }
                )
            
            # Create simulation manager
            simgr = project.factory.simulation_manager(initial_state)
            
            # Explore to find target and avoid unwanted paths
            self._progress_text = "Exploring paths..."
            log_info(f"Looking for: '{self.target_string}', avoiding: '{self.avoid_string}'")
            
            simgr.explore(
                find=lambda s: self.target_string.encode() in s.posix.dumps(1) if self.target_string else False,
                avoid=lambda s: self.avoid_string.encode() in s.posix.dumps(1) if self.avoid_string else False
            )
            
            if simgr.found:
                found_state = simgr.found[0]
                solution = found_state.solver.eval(user_input, cast_to=bytes)
                
                # Clean up solution (remove null bytes)
                try:
                    clean_solution = solution.split(b'\x00')[0] if b'\x00' in solution else solution
                    self.result = clean_solution.decode('utf-8', errors='ignore')
                except:
                    self.result = str(solution)
                    
                self._progress_text = f"Solution found: {self.result}"
                log_info(f"angr found solution: {self.result}")
            else:
                self.result = None
                self._progress_text = "No solution found"
                log_info("angr found no solution")
                
        except Exception as e:
            self.error = str(e)
            log_info(f"Angr solver error: {traceback.format_exc()}")
        
        self._finished = True
    
    def get_progress(self):
        return self._progress_text
    
    def is_finished(self):
        return self._finished

class AngrSolverDialog(QDialog):
    def __init__(self, bv, parent=None):
        super().__init__(parent)
        self.bv = bv
        self.solver_task = None
        self.progress_timer = None
        self.init_ui()
        self.center_window()
        
    def init_ui(self):
        self.setWindowTitle("angr Symbolic Execution Solver")
        self.setMinimumSize(500, 400)
        
        layout = QVBoxLayout()
        
        # Title
        title = QLabel("angr Symbolic Execution Configuration")
        title.setAlignment(Qt.AlignCenter)
        title.setStyleSheet("font-size: 16px; font-weight: bold; margin: 10px;")
        layout.addWidget(title)
        
        # Warning if angr not available
        if not ANGR_AVAILABLE:
            warning_label = QLabel("⚠️ angr is not installed. Please install it via: pip install angr")
            warning_label.setStyleSheet("color: red; font-weight: bold; padding: 10px;")
            warning_label.setWordWrap(True)
            layout.addWidget(warning_label)
        
        # Configuration group
        config_group = QGroupBox("Solver Configuration")
        config_layout = QFormLayout()
        
        # Target string input
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("e.g., Cracked!, Success, Welcome")
        config_layout.addRow("Target String (find):", self.target_input)
        
        # Avoid string input
        self.avoid_input = QLineEdit()
        self.avoid_input.setPlaceholderText("e.g., Try Again!, Failed, Error")
        config_layout.addRow("Avoid String (avoid):", self.avoid_input)
        
        # Input size
        self.size_input = QSpinBox()
        self.size_input.setRange(1, 100)
        self.size_input.setValue(20)
        self.size_input.setToolTip("Number of characters in the symbolic input")
        config_layout.addRow("Input Size:", self.size_input)
        
        # Input method
        self.argv_checkbox = QCheckBox("Use command line arguments (argv)")
        self.argv_checkbox.setChecked(True)
        self.argv_checkbox.setToolTip("If unchecked, uses stdin for input")
        config_layout.addRow("Input Method:", self.argv_checkbox)
        
        config_group.setLayout(config_layout)
        layout.addWidget(config_group)
        
        # Status area
        status_group = QGroupBox("Status")
        status_layout = QVBoxLayout()
        
        self.status_label = QLabel("Ready to solve..." if ANGR_AVAILABLE else "angr not available")
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        
        status_layout.addWidget(self.status_label)
        status_layout.addWidget(self.progress_bar)
        status_group.setLayout(status_layout)
        layout.addWidget(status_group)
        
        # Results area
        results_group = QGroupBox("Results")
        results_layout = QVBoxLayout()
        
        self.results_text = QTextEdit()
        self.results_text.setReadOnly(True)
        self.results_text.setMaximumHeight(100)
        results_layout.addWidget(self.results_text)
        
        results_group.setLayout(results_layout)
        layout.addWidget(results_group)
        
        # Buttons
        button_layout = QHBoxLayout()
        
        self.solve_btn = QPushButton("Solve with angr")
        self.solve_btn.clicked.connect(self.start_solving)
        self.solve_btn.setEnabled(ANGR_AVAILABLE)
        button_layout.addWidget(self.solve_btn)
        
        self.clear_btn = QPushButton("Clear Results")
        self.clear_btn.clicked.connect(self.clear_results)
        button_layout.addWidget(self.clear_btn)
        
        button_layout.addStretch()
        
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(self.close_dialog)
        button_layout.addWidget(close_btn)
        
        layout.addLayout(button_layout)
        
        self.setLayout(layout)
        
    def center_window(self):
        """Center the window on the screen"""
        screen_geometry = QApplication.primaryScreen().availableGeometry()
        x = (screen_geometry.width() - self.width()) // 2
        y = (screen_geometry.height() - self.height()) // 2
        self.move(x, y)
    
    def start_solving(self):
        """Start the angr solving process"""
        if not ANGR_AVAILABLE:
            show_message_box(
                "angr Not Available",
                "angr is not installed in Binary Ninja's Python environment.\n\n"
                "Please install it via: pip install angr\n\n"
                "You may need to install it in Binary Ninja's specific Python environment.",
                MessageBoxButtonSet.OKButtonSet,
                MessageBoxIcon.ErrorIcon
            )
            return
            
        target_str = self.target_input.text().strip()
        avoid_str = self.avoid_input.text().strip()
        input_size = self.size_input.value()
        use_argv = self.argv_checkbox.isChecked()
        
        if not target_str:
            show_message_box(
                "Configuration Error",
                "Please enter a target string to find.",
                MessageBoxButtonSet.OKButtonSet,
                MessageBoxIcon.ErrorIcon
            )
            return
        
        # Update UI
        self.solve_btn.setEnabled(False)
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)  # Indeterminate progress
        self.status_label.setText("Starting symbolic execution...")
        
        # Create and start solver task
        self.solver_task = AngrSolverTask(self.bv, target_str, avoid_str, input_size, use_argv)
        
        # Use a timer to periodically check progress
        self.progress_timer = QTimer()
        self.progress_timer.timeout.connect(self.check_progress)
        self.progress_timer.start(500)  # Check every 500ms
        
        self.solver_task.start()
    
    def check_progress(self):
        """Check for task completion and update progress"""
        if self.solver_task:
            # Update progress text
            if hasattr(self.solver_task, 'get_progress'):
                progress_text = self.solver_task.get_progress()
                self.status_label.setText(progress_text)
            
            # Check if task is finished using our custom method
            if hasattr(self.solver_task, 'is_finished') and self.solver_task.is_finished():
                self.progress_timer.stop()
                self.solving_finished()
    
    def solving_finished(self):
        """Handle completion of the solving process"""
        self.solve_btn.setEnabled(True)
        self.progress_bar.setVisible(False)
        
        if self.solver_task:
            if self.solver_task.error:
                self.status_label.setText(f"Error: {self.solver_task.error}")
                self.results_text.setText(f"Error during symbolic execution:\n{self.solver_task.error}")
                show_message_box(
                    "Solver Error",
                    f"An error occurred during symbolic execution:\n{self.solver_task.error}",
                    MessageBoxButtonSet.OKButtonSet,
                    MessageBoxIcon.ErrorIcon
                )
            elif self.solver_task.result:
                self.status_label.setText("Solution found!")
                result_text = f"Solution: {self.solver_task.result}\n\n"
                result_text += f"Hex: {self.solver_task.result.encode().hex()}\n"
                result_text += f"Length: {len(self.solver_task.result)} characters"
                self.results_text.setText(result_text)
                
                show_message_box(
                    "Solution Found!",
                    f"Symbolic execution found a solution:\n\n{self.solver_task.result}",
                    MessageBoxButtonSet.OKButtonSet,
                    MessageBoxIcon.InformationIcon
                )
            else:
                self.status_label.setText("No solution found")
                self.results_text.setText("No solution found with the given constraints.")
                
                show_message_box(
                    "No Solution",
                    "No solution was found with the current configuration.\n\nTry adjusting the target/avoid strings or input size.",
                    MessageBoxButtonSet.OKButtonSet,
                    MessageBoxIcon.InformationIcon
                )
    
    def clear_results(self):
        """Clear the results text area"""
        self.results_text.clear()
        self.status_label.setText("Ready to solve...")
    
    def close_dialog(self):
        """Close the dialog and clean up"""
        global _angr_dialog
        if self.progress_timer and self.progress_timer.isActive():
            self.progress_timer.stop()
        _angr_dialog = None
        self.close()

def show_angr_solver_dialog(bv):
    """Show the angr symbolic execution solver dialog"""
    global _angr_dialog
    
    # Close existing dialog if open
    if _angr_dialog is not None:
        _angr_dialog.close()
        _angr_dialog = None
    
    # Create and show the dialog
    _angr_dialog = AngrSolverDialog(bv)
    _angr_dialog.show()
    _angr_dialog.raise_()
    _angr_dialog.activateWindow()

# Only register the command if angr is available
if ANGR_AVAILABLE:
    PluginCommand.register(
        "nyxFault-Binja\\angr Symbolic Solver", 
        "Use angr symbolic execution to find inputs that reach target states",
        show_angr_solver_dialog
    )
else:
    # Register a command that shows an error message
    def show_angr_error(bv):
        show_message_box(
            "angr Not Available",
            "angr is not installed in Binary Ninja's Python environment.\n\n"
            "Please install it via: pip install angr\n\n"
            "You may need to install it in Binary Ninja's specific Python environment:\n"
            "1. Open Binary Ninja\n"
            "2. Go to Python Console\n" 
            "3. Run: import pip; pip.main(['install', 'angr'])",
            MessageBoxButtonSet.OKButtonSet,
            MessageBoxIcon.ErrorIcon
        )
    
    PluginCommand.register(
        "nyxFault-Binja\\angr Symbolic Solver", 
        "Use angr symbolic execution to find inputs that reach target states (angr not installed)",
        show_angr_error
    )