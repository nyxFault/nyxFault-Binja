from binaryninja.flowgraph import FlowGraph, FlowGraphNode, EdgeStyle
from binaryninja.enums import EdgePenStyle, ThemeColor, BranchType, HighlightStandardColor
from binaryninja import show_graph_report, PluginCommand, get_text_line_input

def launch_user_flow_graph(bv):
    # Step 1: Get number of nodes
    result = get_text_line_input(
        "How many nodes?\n(e.g. 3)", "Flowgraph Builder")
    if result is None:
        print("Cancelled.")
        return
    try:
        num_of_nodes = int(result)
        if num_of_nodes < 1 or num_of_nodes > 50:
            print("Please enter a reasonable number of nodes (1-50).")
            return
    except Exception:
        print("Invalid number of nodes")
        return

    # Step 2: Create the nodes/graph
    graph = FlowGraph()
    nodes = []
    for i in range(num_of_nodes):
        node = FlowGraphNode(graph)
        node.lines = [f"Node {i}"]
        graph.append(node)
        nodes.append(node)

    # Highlight colors cycle
    colors = [
        HighlightStandardColor.RedHighlightColor,
        HighlightStandardColor.GreenHighlightColor,
        HighlightStandardColor.CyanHighlightColor,
        HighlightStandardColor.MagentaHighlightColor,
        HighlightStandardColor.YellowHighlightColor,
        HighlightStandardColor.BlueHighlightColor
    ]
    for i, node in enumerate(nodes):
        node.highlight = colors[i % len(colors)]

    # Step 3: Get edge connections (comma-separated)
    edges_str = get_text_line_input(
    "Enter edge pairs as 'src dst, src dst, ...'\nExample: 0 1, 0 2, 1 2", "Flowgraph Builder"
    )
    if edges_str is None:
        print("Cancelled.")
        return

    # Only decode if it's bytes
    if isinstance(edges_str, bytes):
        edges_str = edges_str.decode()

    pairs = [p.strip() for p in edges_str.strip().split(",") if p.strip()]

    edge_style = EdgeStyle(EdgePenStyle.SolidLine, 2, ThemeColor.AddressColor)

    
    for idx, pair in enumerate(pairs):
        try:
            src_idx, dst_idx = map(int, pair.split())
            if 0 <= src_idx < num_of_nodes and 0 <= dst_idx < num_of_nodes:
                nodes[src_idx].add_outgoing_edge(BranchType.UnconditionalBranch, nodes[dst_idx], edge_style)
            else:
                print(f"Invalid node indices for edge: '{pair}'")
        except Exception as e:
            print(f"Invalid input for edge: '{pair}': {e}")

    # Step 4: Show the graph
    show_graph_report("User Defined Flow Graph", graph)

PluginCommand.register(
    "nyxFault-Binja\\User Flow Graph Builder",
    "Build and visualize a custom flowgraph—simplified comma-separated edge entry.",
    launch_user_flow_graph
)
