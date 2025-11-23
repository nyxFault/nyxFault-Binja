from binaryninja import (
    show_graph_report,
    PluginCommand,
    get_text_line_input,
    show_message_box,
    MessageBoxButtonSet,
    MessageBoxIcon,
    enums
)
from binaryninja.flowgraph import FlowGraph, FlowGraphNode, EdgeStyle
from binaryninja.enums import EdgePenStyle, ThemeColor, BranchType, HighlightStandardColor, MediumLevelILOperation

def show_callees_graph(bv):
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

    graph = FlowGraph()
    center_node = FlowGraphNode(graph)
    center_node.lines = [f"Source: {func.name} @ {hex(func.start)}"]
    center_node.highlight = HighlightStandardColor.CyanHighlightColor
    graph.append(center_node)

    edge_style = EdgeStyle(EdgePenStyle.SolidLine, 2, ThemeColor.AddressColor)
    color_cycle = [
        HighlightStandardColor.RedHighlightColor,
        HighlightStandardColor.GreenHighlightColor,
        HighlightStandardColor.MagentaHighlightColor,
        HighlightStandardColor.YellowHighlightColor,
        HighlightStandardColor.BlueHighlightColor
    ]
    
    for idx, (callee_name, callee_addr, callsite_addr) in enumerate(sorted(callees)):
        callee_node = FlowGraphNode(graph)
        
        lines = [f"{callee_name}"]
        if callee_addr:
            lines.append(f"({hex(callee_addr)})")
        lines.append(f"called @ {hex(callsite_addr)}")
        
        callee_node.lines = lines
        callee_node.highlight = color_cycle[idx % len(color_cycle)]
        graph.append(callee_node)
        center_node.add_outgoing_edge(BranchType.UnconditionalBranch, callee_node, edge_style)

    show_graph_report(f"Callees of {func.name}", graph)

PluginCommand.register(
    "nyxFault-Binja\\Callees Flowgraph",
    "Draw a flowgraph of all callees from a specified function (with imports & callsites).",
    show_callees_graph
)