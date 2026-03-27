"""
tf-state-explorer — graph.py

Reconstructs the dependency graph between Terraform resources from the
`dependencies` field stored in each resource instance within the state file.

The graph is a directed acyclic graph (DAG) where an edge A -> B means
"resource A depends on resource B" (B must exist before A can be created).

Public API
----------
    from graph import build, orphans, cycles, to_dot, to_adjacency

    state = StateParser().parse("terraform.tfstate")
    graph = build(state)

    print(f"{graph.node_count} nodes, {graph.edge_count} edges")

    for node in orphans(graph):
        print("No dependencies:", node)

    for cycle in cycles(graph):
        print("Cycle detected:", " -> ".join(cycle))

    print(to_dot(graph))   # Graphviz DOT format
"""

from __future__ import annotations

from dataclasses import dataclass

from parser import ParsedState, TFResource


# ---------------------------------------------------------------------------
# Core data structures
# ---------------------------------------------------------------------------


@dataclass
class Node:
    """
    A single node in the dependency graph, representing one Terraform resource.

    Attributes:
        address:  Full Terraform address, e.g. "module.vpc.aws_instance.web".
        resource: The underlying TFResource this node was built from.
    """

    address: str
    resource: TFResource


@dataclass
class Edge:
    """
    A directed edge in the dependency graph.

    An edge from `source` to `target` means:
    "source depends on target" — target must be created before source.

    Attributes:
        source: Address of the dependent resource.
        target: Address of the resource being depended upon.
    """

    source: str
    target: str


@dataclass
class DependencyGraph:
    """
    The full dependency graph extracted from a Terraform state.

    Attributes:
        nodes:      Dict mapping resource address to its Node.
        edges:      List of all directed dependency edges.
        adjacency:  Dict mapping each address to the set of addresses it
                    depends on (outgoing edges).
        reverse:    Dict mapping each address to the set of addresses that
                    depend on it (incoming edges — reverse adjacency).
    """

    nodes: dict[str, Node]
    edges: list[Edge]
    adjacency: dict[str, set[str]]  # address -> set of dependencies
    reverse: dict[str, set[str]]  # address -> set of dependents

    @property
    def node_count(self) -> int:
        """Total number of nodes in the graph."""
        return len(self.nodes)

    @property
    def edge_count(self) -> int:
        """Total number of directed edges in the graph."""
        return len(self.edges)

    def dependencies_of(self, address: str) -> set[str]:
        """
        Returns the set of addresses that the given resource depends on.

        Args:
            address: Full Terraform address of the resource.

        Returns:
            Set of dependency addresses (empty if none or address unknown).
        """
        return self.adjacency.get(address, set())

    def dependents_of(self, address: str) -> set[str]:
        """
        Returns the set of addresses that depend on the given resource.

        Args:
            address: Full Terraform address of the resource.

        Returns:
            Set of dependent addresses (empty if none or address unknown).
        """
        return self.reverse.get(address, set())


# ---------------------------------------------------------------------------
# Graph construction
# ---------------------------------------------------------------------------


def build(state: ParsedState) -> DependencyGraph:
    """
    Builds a dependency graph from a parsed Terraform state.

    Each managed resource and data source becomes a node.  The `dependencies`
    field on each resource instance is used to construct directed edges.

    Dangling references (dependencies pointing to addresses not present in the
    state) are silently ignored — this can happen with remote state data
    sources or resources removed from state without updating dependencies.

    Args:
        state: A ParsedState returned by StateParser.parse().

    Returns:
        A DependencyGraph with all nodes and edges populated.
    """
    nodes: dict[str, Node] = {}
    edges: list[Edge] = []
    adjacency: dict[str, set[str]] = {}
    reverse: dict[str, set[str]] = {}

    # Register all resources and data sources as nodes
    for resource in state.all_resources:
        address = resource.address
        nodes[address] = Node(address=address, resource=resource)
        adjacency[address] = set()
        reverse[address] = set()

    # Build edges from the dependencies field
    for resource in state.all_resources:
        source = resource.address
        for dep in resource.dependencies:
            # Normalise the dependency address — Terraform sometimes stores
            # addresses without the "data." prefix for data sources
            target = dep
            if target not in nodes:
                # Try prefixing with "data." in case it was omitted
                data_target = (
                    f"data.{target}" if not target.startswith("data.") else target
                )
                if data_target in nodes:
                    target = data_target
                else:
                    # Dangling reference — skip silently
                    continue

            edge = Edge(source=source, target=target)
            edges.append(edge)
            adjacency[source].add(target)
            reverse[target].add(source)

    return DependencyGraph(
        nodes=nodes,
        edges=edges,
        adjacency=adjacency,
        reverse=reverse,
    )


# ---------------------------------------------------------------------------
# Graph analysis
# ---------------------------------------------------------------------------


def orphans(graph: DependencyGraph) -> list[str]:
    """
    Returns addresses of managed resources with no outgoing dependencies.

    An orphan resource does not depend on any other resource in the state.
    This is normal for foundational resources (VPCs, IAM policies, ...) but
    may also indicate a missing dependency declaration.

    Only managed resources are returned — data sources are excluded because
    they are inherently independent read-only resources.

    Args:
        graph: A DependencyGraph returned by build().

    Returns:
        A sorted list of resource addresses with no dependencies.
    """
    result = []
    for address, node in graph.nodes.items():
        if node.resource.mode != "managed":
            continue
        if not graph.adjacency.get(address):
            result.append(address)
    return sorted(result)


def roots(graph: DependencyGraph) -> list[str]:
    """
    Returns addresses of resources that nothing else depends on.

    Root nodes are the "leaves" in the dependency tree — they are the last
    resources to be created and the first to be destroyed.  In a typical
    Terraform setup these are the application-layer resources (EC2 instances,
    RDS databases, ...) that depend on networking resources but are not
    themselves depended upon.

    Args:
        graph: A DependencyGraph returned by build().

    Returns:
        A sorted list of resource addresses with no incoming edges.
    """
    result = []
    for address in graph.nodes:
        if not graph.reverse.get(address):
            result.append(address)
    return sorted(result)


def cycles(graph: DependencyGraph) -> list[list[str]]:
    """
    Detects cycles in the dependency graph using DFS.

    Terraform itself prevents cycles at plan time, so a healthy state file
    should never contain cycles.  This function exists as a safety net for
    corrupted or manually edited state files.

    Args:
        graph: A DependencyGraph returned by build().

    Returns:
        A list of cycles, where each cycle is a list of addresses forming
        a closed loop.  Returns an empty list if the graph is acyclic.
    """
    # Standard DFS-based cycle detection
    # Colors: 0 = unvisited, 1 = in progress, 2 = done
    color: dict[str, int] = {addr: 0 for addr in graph.nodes}
    parent: dict[str, str | None] = {addr: None for addr in graph.nodes}
    found_cycles: list[list[str]] = []

    def dfs(node: str) -> None:
        color[node] = 1  # mark as in progress

        for neighbor in graph.adjacency.get(node, set()):
            if color[neighbor] == 1:
                # Back edge found — reconstruct the cycle
                cycle = [neighbor]
                current = node
                while current != neighbor:
                    cycle.append(current)
                    current = parent[current]  # type: ignore[assignment]
                cycle.append(neighbor)
                cycle.reverse()
                found_cycles.append(cycle)
            elif color[neighbor] == 0:
                parent[neighbor] = node
                dfs(neighbor)

        color[node] = 2  # mark as done

    for address in graph.nodes:
        if color[address] == 0:
            dfs(address)

    return found_cycles


def depth(graph: DependencyGraph, address: str) -> int:
    """
    Returns the maximum dependency depth of a resource.

    Depth 0 means the resource has no dependencies (a foundation resource).
    Depth 1 means it depends only on depth-0 resources.
    And so on.

    Uses memoized DFS to avoid recomputing depths for shared dependencies.

    Args:
        graph:   A DependencyGraph returned by build().
        address: Full address of the resource to measure.

    Returns:
        An integer >= 0 representing the maximum dependency chain length.
    """
    memo: dict[str, int] = {}

    def _depth(addr: str, visited: set[str]) -> int:
        if addr in memo:
            return memo[addr]
        deps = graph.adjacency.get(addr, set())
        if not deps:
            memo[addr] = 0
            return 0
        # Guard against cycles (should not happen in valid state)
        if addr in visited:
            return 0
        visited = visited | {addr}
        result = 1 + max(_depth(d, visited) for d in deps)
        memo[addr] = result
        return result

    return _depth(address, set())


# ---------------------------------------------------------------------------
# Export functions
# ---------------------------------------------------------------------------


def to_dot(
    graph: DependencyGraph,
    *,
    title: str = "terraform_dependencies",
    highlight: set[str] | None = None,
) -> str:
    """
    Exports the dependency graph in Graphviz DOT format.

    The output can be piped to `dot -Tsvg -o graph.svg` or rendered online
    at https://dreampuf.github.io/GraphvizOnline/

    Nodes are grouped by provider using Graphviz subgraphs.
    Highlighted nodes (e.g. resources with secrets) are rendered in red.

    Args:
        graph:     A DependencyGraph returned by build().
        title:     Graph title used as the DOT digraph name.
        highlight: Optional set of addresses to render in red.
                   Useful for flagging resources with detected secrets.

    Returns:
        A string containing a valid Graphviz DOT document.

    Example:
        dot_output = to_dot(graph)
        with open("graph.dot", "w") as f:
            f.write(dot_output)
        # then: dot -Tsvg graph.dot -o graph.svg
    """
    highlight = highlight or set()
    lines = [
        f'digraph "{title}" {{',
        "  rankdir=LR;",
        '  node [shape=box fontname="Helvetica" fontsize=10];',
        '  edge [fontsize=9 color="#666666"];',
        "",
    ]

    # Group nodes by provider using subgraphs
    by_provider: dict[str, list[str]] = {}
    for address, node in graph.nodes.items():
        provider = node.resource.provider
        by_provider.setdefault(provider, []).append(address)

    for provider, addresses in sorted(by_provider.items()):
        lines.append(f'  subgraph "cluster_{provider}" {{')
        lines.append(f'    label="{provider}";')
        lines.append("    style=dashed;")
        for address in sorted(addresses):
            # Escape quotes in address for DOT safety
            safe = address.replace('"', '\\"')
            if address in highlight:
                lines.append(
                    f'    "{safe}" [color=red style=filled fillcolor="#ffcccc"];'
                )
            else:
                lines.append(f'    "{safe}";')
        lines.append("  }")
        lines.append("")

    # Emit edges
    for edge in sorted(graph.edges, key=lambda e: (e.source, e.target)):
        src = edge.source.replace('"', '\\"')
        tgt = edge.target.replace('"', '\\"')
        lines.append(f'  "{src}" -> "{tgt}";')

    lines.append("}")
    return "\n".join(lines)


def to_adjacency(graph: DependencyGraph) -> dict[str, list[str]]:
    """
    Exports the graph as a plain adjacency dict for JSON serialisation.

    Converts the internal set-based adjacency to sorted lists so the output
    is deterministic and JSON-serialisable.

    Args:
        graph: A DependencyGraph returned by build().

    Returns:
        A dict mapping each address to a sorted list of its dependencies.

    Example:
        import json
        adj = to_adjacency(graph)
        print(json.dumps(adj, indent=2))
    """
    return {address: sorted(deps) for address, deps in sorted(graph.adjacency.items())}
