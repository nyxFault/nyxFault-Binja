from binaryninja import (
    show_graph_report, 
    PluginCommand, 
    get_text_line_input, 
    show_message_box, 
    MessageBoxButtonSet, 
    MessageBoxIcon,
    enums,
    log_info
)
from binaryninja.flowgraph import FlowGraph, FlowGraphNode, EdgeStyle
from binaryninja.enums import EdgePenStyle, ThemeColor, BranchType, HighlightStandardColor, MediumLevelILOperation


def show_callers_graph(bv):
    fn_name = get_text_line_input("Enter function name (e.g., main):", "Callers Flowgraph")
    if not fn_name:
        return
    if isinstance(fn_name, bytes):
        fn_name = fn_name.decode()

    fn_name = fn_name.strip()
    
    # First, try to find the function by name (defined functions)
    funcs = bv.get_functions_by_name(fn_name)
    
    # If not found, try to find it as an imported function
    if not funcs:
        # Let's search for calls to functions that match our target name by examining all call instructions in the binary
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
            # We found calls to functions matching our target name
            # Let the user choose which one if there are multiple
            if len(callers_found) == 1:
                target_name = list(callers_found.keys())[0]
            else:
                # If multiple matches, show the first one for now
                target_name = list(callers_found.keys())[0]
                log_info(f"Multiple matches found: {list(callers_found.keys())}. Using: {target_name}")
            
            # Create the graph
            graph = FlowGraph()
            center_node = FlowGraphNode(graph)
            center_node.lines = [f"Target: {target_name} (imported/resolved)"]
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
            
            callers_list = callers_found[target_name]
            for idx, (caller_func, callsite_addr) in enumerate(callers_list):
                caller_node = FlowGraphNode(graph)
                caller_node.lines = [
                    f"{caller_func.name}",
                    f"calls @ {hex(callsite_addr)}"
                ]
                caller_node.highlight = color_cycle[idx % len(color_cycle)]
                graph.append(caller_node)
                caller_node.add_outgoing_edge(BranchType.UnconditionalBranch, center_node, edge_style)

            show_graph_report(f"Callers of {target_name}", graph)
            return
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
    
    # If we found a regular function (not imported)
    func = funcs[0]
    callers = bv.get_callers(func.start)
    if not callers:
        show_message_box(
            "No Callers",
            f"No callers found for function '{func.name}'.",
            MessageBoxButtonSet.OKButtonSet,
            MessageBoxIcon.InformationIcon
        )
        return

    graph = FlowGraph()
    center_node = FlowGraphNode(graph)
    center_node.lines = [f"Target: {func.name} @ {hex(func.start)}"]
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
    for idx, caller_ref in enumerate(callers):
        caller_func = caller_ref.function
        callsite = caller_ref.address
        if caller_func is None:
            continue
        caller_node = FlowGraphNode(graph)
        caller_node.lines = [
            f"{caller_func.name}",
            f"calls @ {hex(callsite)}"
        ]
        caller_node.highlight = color_cycle[idx % len(color_cycle)]
        graph.append(caller_node)
        caller_node.add_outgoing_edge(BranchType.UnconditionalBranch, center_node, edge_style)

    show_graph_report(f"Callers of {func.name}", graph)

PluginCommand.register(
    "nyxFault-Binja\\Callers Flowgraph", 
    "Draw a flowgraph of all callers of a specified function (including imported functions).",
    show_callers_graph
)