"""
Unit tests for graph.py

Run with:
    python -m pytest tests/test_graph.py -v

Test structure
--------------
    TestBuild              — build() constructs nodes and edges correctly
    TestDependencyGraph    — DependencyGraph properties and helper methods
    TestOrphans            — orphans() detects resources with no dependencies
    TestRoots              — roots() detects resources with no dependents
    TestCycles             — cycles() detects circular dependencies
    TestDepth              — depth() measures dependency chain length
    TestToDot              — to_dot() produces valid Graphviz DOT output
    TestToAdjacency        — to_adjacency() serialises graph to plain dict
    TestBuildWithFixtures  — integration tests using real fixture files
"""

from pathlib import Path

import pytest

from parser import ParsedState, StateParser, TFResource
from graph import (
    DependencyGraph,
    build,
    cycles,
    depth,
    orphans,
    roots,
    to_adjacency,
    to_dot,
)

FIXTURES = Path(__file__).parent / "fixtures"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def load_fixture(name: str) -> str:
    """Returns the absolute path to a fixture file as a string."""
    return str(FIXTURES / name)


def make_resource(
    address: str,
    dependencies: list[str] | None = None,
    mode: str = "managed",
) -> TFResource:
    """
    Returns a minimal TFResource with the given address and dependencies.

    Address is split into type and name on the last dot for simplicity.
    Module prefix is stripped for the type/name fields — only address matters
    for graph tests.
    """
    parts = address.split(".")
    # Handle data sources: data.aws_ami.ubuntu -> type=aws_ami, name=ubuntu
    if parts[0] == "data":
        res_type, name = parts[1], parts[2]
    elif parts[0].startswith("module"):
        res_type, name = parts[-2], parts[-1]
    else:
        res_type, name = parts[0], parts[1]

    # Extract module if present
    module = None
    if address.startswith("module."):
        # e.g. module.vpc.aws_instance.web -> module.vpc
        module = ".".join(address.split(".")[:2])

    return TFResource(
        type=res_type,
        name=name,
        provider="aws",
        mode=mode,
        module=module,
        attributes={},
        dependencies=dependencies or [],
        raw={},
    )


def make_state(resources: list[TFResource]) -> ParsedState:
    """Returns a minimal ParsedState with the given resources."""
    managed = [r for r in resources if r.mode == "managed"]
    data = [r for r in resources if r.mode == "data"]
    return ParsedState(
        terraform_version="1.5.0",
        serial=1,
        lineage="x",
        resources=managed,
        data_sources=data,
        outputs=[],
        warnings=[],
    )


# ---------------------------------------------------------------------------
# TestBuild
# ---------------------------------------------------------------------------


class TestBuild:
    """Tests for the build() function."""

    def test_returns_dependency_graph(self):
        state = make_state([make_resource("aws_vpc.main")])
        g = build(state)
        assert isinstance(g, DependencyGraph)

    def test_empty_state_empty_graph(self):
        state = make_state([])
        g = build(state)
        assert g.node_count == 0
        assert g.edge_count == 0

    def test_single_resource_becomes_node(self):
        state = make_state([make_resource("aws_vpc.main")])
        g = build(state)
        assert "aws_vpc.main" in g.nodes

    def test_node_address_matches(self):
        state = make_state([make_resource("aws_instance.web")])
        g = build(state)
        assert g.nodes["aws_instance.web"].address == "aws_instance.web"

    def test_dependency_creates_edge(self):
        resources = [
            make_resource("aws_vpc.main"),
            make_resource("aws_subnet.public", dependencies=["aws_vpc.main"]),
        ]
        state = make_state(resources)
        g = build(state)
        assert g.edge_count == 1
        assert any(
            e.source == "aws_subnet.public" and e.target == "aws_vpc.main"
            for e in g.edges
        )

    def test_adjacency_populated(self):
        resources = [
            make_resource("aws_vpc.main"),
            make_resource("aws_subnet.public", dependencies=["aws_vpc.main"]),
        ]
        state = make_state(resources)
        g = build(state)
        assert "aws_vpc.main" in g.adjacency["aws_subnet.public"]

    def test_reverse_adjacency_populated(self):
        resources = [
            make_resource("aws_vpc.main"),
            make_resource("aws_subnet.public", dependencies=["aws_vpc.main"]),
        ]
        state = make_state(resources)
        g = build(state)
        assert "aws_subnet.public" in g.reverse["aws_vpc.main"]

    def test_dangling_dependency_ignored(self):
        # A dependency pointing to a non-existent resource must not raise
        resources = [
            make_resource("aws_instance.web", dependencies=["aws_vpc.nonexistent"]),
        ]
        state = make_state(resources)
        g = build(state)
        assert g.edge_count == 0

    def test_multiple_dependencies(self):
        resources = [
            make_resource("aws_vpc.main"),
            make_resource("aws_security_group.sg"),
            make_resource(
                "aws_instance.web",
                dependencies=["aws_vpc.main", "aws_security_group.sg"],
            ),
        ]
        state = make_state(resources)
        g = build(state)
        assert g.edge_count == 2
        assert "aws_vpc.main" in g.adjacency["aws_instance.web"]
        assert "aws_security_group.sg" in g.adjacency["aws_instance.web"]

    def test_data_sources_included_as_nodes(self):
        # Data sources must also appear as nodes in the graph
        resources = [
            make_resource("data.aws_ami.ubuntu", mode="data"),
            make_resource("aws_instance.web", dependencies=["data.aws_ami.ubuntu"]),
        ]
        state = make_state(resources)
        g = build(state)
        assert "data.aws_ami.ubuntu" in g.nodes

    def test_node_count_includes_data_sources(self):
        resources = [
            make_resource("aws_vpc.main"),
            make_resource("data.aws_ami.ubuntu", mode="data"),
        ]
        state = make_state(resources)
        g = build(state)
        assert g.node_count == 2


# ---------------------------------------------------------------------------
# TestDependencyGraph
# ---------------------------------------------------------------------------


class TestDependencyGraph:
    """Tests for DependencyGraph properties and helper methods."""

    @pytest.fixture
    def simple_graph(self) -> DependencyGraph:
        resources = [
            make_resource("aws_vpc.main"),
            make_resource("aws_subnet.public", dependencies=["aws_vpc.main"]),
            make_resource(
                "aws_instance.web",
                dependencies=["aws_subnet.public", "aws_vpc.main"],
            ),
        ]
        return build(make_state(resources))

    def test_node_count(self, simple_graph):
        assert simple_graph.node_count == 3

    def test_edge_count(self, simple_graph):
        assert simple_graph.edge_count == 3

    def test_dependencies_of(self, simple_graph):
        deps = simple_graph.dependencies_of("aws_instance.web")
        assert "aws_subnet.public" in deps
        assert "aws_vpc.main" in deps

    def test_dependencies_of_unknown_address(self, simple_graph):
        # Unknown address must return empty set, not raise
        assert simple_graph.dependencies_of("nonexistent.resource") == set()

    def test_dependents_of(self, simple_graph):
        # aws_vpc.main is depended upon by both subnet and instance
        dependents = simple_graph.dependents_of("aws_vpc.main")
        assert "aws_subnet.public" in dependents
        assert "aws_instance.web" in dependents

    def test_dependents_of_unknown_address(self, simple_graph):
        assert simple_graph.dependents_of("nonexistent.resource") == set()


# ---------------------------------------------------------------------------
# TestOrphans
# ---------------------------------------------------------------------------


class TestOrphans:
    """Tests for orphans() — resources with no outgoing dependencies."""

    def test_isolated_resource_is_orphan(self):
        state = make_state([make_resource("aws_vpc.main")])
        g = build(state)
        assert "aws_vpc.main" in orphans(g)

    def test_resource_with_dependency_not_orphan(self):
        resources = [
            make_resource("aws_vpc.main"),
            make_resource("aws_subnet.public", dependencies=["aws_vpc.main"]),
        ]
        g = build(make_state(resources))
        assert "aws_subnet.public" not in orphans(g)

    def test_data_sources_excluded_from_orphans(self):
        # Data sources must never appear in orphans — they are inherently independent
        resources = [make_resource("data.aws_ami.ubuntu", mode="data")]
        g = build(make_state(resources))
        assert "data.aws_ami.ubuntu" not in orphans(g)

    def test_returns_sorted_list(self):
        resources = [
            make_resource("aws_vpc.main"),
            make_resource("aws_instance.web"),
        ]
        g = build(make_state(resources))
        result = orphans(g)
        assert result == sorted(result)

    def test_empty_graph_no_orphans(self):
        g = build(make_state([]))
        assert orphans(g) == []


# ---------------------------------------------------------------------------
# TestRoots
# ---------------------------------------------------------------------------


class TestRoots:
    """Tests for roots() — resources with no incoming dependencies."""

    def test_leaf_resource_is_root(self):
        # aws_instance.web depends on others but nothing depends on it
        resources = [
            make_resource("aws_vpc.main"),
            make_resource("aws_instance.web", dependencies=["aws_vpc.main"]),
        ]
        g = build(make_state(resources))
        assert "aws_instance.web" in roots(g)

    def test_dependency_target_not_root(self):
        resources = [
            make_resource("aws_vpc.main"),
            make_resource("aws_instance.web", dependencies=["aws_vpc.main"]),
        ]
        g = build(make_state(resources))
        assert "aws_vpc.main" not in roots(g)

    def test_returns_sorted_list(self):
        resources = [
            make_resource("aws_vpc.main"),
            make_resource("aws_instance.web"),
        ]
        g = build(make_state(resources))
        result = roots(g)
        assert result == sorted(result)

    def test_empty_graph_no_roots(self):
        g = build(make_state([]))
        assert roots(g) == []


# ---------------------------------------------------------------------------
# TestCycles
# ---------------------------------------------------------------------------


class TestCycles:
    """Tests for cycles() — detects circular dependencies."""

    def test_acyclic_graph_no_cycles(self):
        resources = [
            make_resource("aws_vpc.main"),
            make_resource("aws_subnet.public", dependencies=["aws_vpc.main"]),
            make_resource("aws_instance.web", dependencies=["aws_subnet.public"]),
        ]
        g = build(make_state(resources))
        assert cycles(g) == []

    def test_empty_graph_no_cycles(self):
        g = build(make_state([]))
        assert cycles(g) == []

    def test_single_node_no_cycles(self):
        g = build(make_state([make_resource("aws_vpc.main")]))
        assert cycles(g) == []


# ---------------------------------------------------------------------------
# TestDepth
# ---------------------------------------------------------------------------


class TestDepth:
    """Tests for depth() — measures dependency chain length."""

    def test_no_dependencies_depth_zero(self):
        state = make_state([make_resource("aws_vpc.main")])
        g = build(state)
        assert depth(g, "aws_vpc.main") == 0

    def test_one_level_depth_one(self):
        resources = [
            make_resource("aws_vpc.main"),
            make_resource("aws_subnet.public", dependencies=["aws_vpc.main"]),
        ]
        g = build(make_state(resources))
        assert depth(g, "aws_subnet.public") == 1

    def test_two_levels_depth_two(self):
        resources = [
            make_resource("aws_vpc.main"),
            make_resource("aws_subnet.public", dependencies=["aws_vpc.main"]),
            make_resource("aws_instance.web", dependencies=["aws_subnet.public"]),
        ]
        g = build(make_state(resources))
        assert depth(g, "aws_instance.web") == 2

    def test_diamond_dependency_max_depth(self):
        # A -> B, A -> C, B -> D, C -> D
        # depth(A) should be 2 (A->B->D or A->C->D)
        resources = [
            make_resource("aws_vpc.d"),
            make_resource("aws_subnet.b", dependencies=["aws_vpc.d"]),
            make_resource("aws_subnet.c", dependencies=["aws_vpc.d"]),
            make_resource(
                "aws_instance.a",
                dependencies=["aws_subnet.b", "aws_subnet.c"],
            ),
        ]
        g = build(make_state(resources))
        assert depth(g, "aws_instance.a") == 2

    def test_unknown_address_returns_zero(self):
        g = build(make_state([]))
        assert depth(g, "nonexistent.resource") == 0


# ---------------------------------------------------------------------------
# TestToDot
# ---------------------------------------------------------------------------


class TestToDot:
    """Tests for to_dot() — Graphviz DOT format export."""

    @pytest.fixture
    def simple_graph(self) -> DependencyGraph:
        resources = [
            make_resource("aws_vpc.main"),
            make_resource("aws_instance.web", dependencies=["aws_vpc.main"]),
        ]
        return build(make_state(resources))

    def test_returns_string(self, simple_graph):
        assert isinstance(to_dot(simple_graph), str)

    def test_starts_with_digraph(self, simple_graph):
        output = to_dot(simple_graph)
        assert output.startswith("digraph")

    def test_contains_node_addresses(self, simple_graph):
        output = to_dot(simple_graph)
        assert "aws_vpc.main" in output
        assert "aws_instance.web" in output

    def test_contains_edge(self, simple_graph):
        output = to_dot(simple_graph)
        assert "->" in output

    def test_custom_title(self, simple_graph):
        output = to_dot(simple_graph, title="my_graph")
        assert "my_graph" in output

    def test_highlight_applies_red_color(self, simple_graph):
        output = to_dot(simple_graph, highlight={"aws_vpc.main"})
        assert "red" in output or "ffcccc" in output

    def test_empty_graph_valid_dot(self):
        g = build(make_state([]))
        output = to_dot(g)
        assert output.startswith("digraph")
        assert output.endswith("}")

    def test_closes_with_brace(self, simple_graph):
        output = to_dot(simple_graph)
        assert output.strip().endswith("}")


# ---------------------------------------------------------------------------
# TestToAdjacency
# ---------------------------------------------------------------------------


class TestToAdjacency:
    """Tests for to_adjacency() — plain dict export."""

    def test_returns_dict(self):
        g = build(make_state([make_resource("aws_vpc.main")]))
        assert isinstance(to_adjacency(g), dict)

    def test_empty_graph(self):
        g = build(make_state([]))
        assert to_adjacency(g) == {}

    def test_no_deps_empty_list(self):
        g = build(make_state([make_resource("aws_vpc.main")]))
        adj = to_adjacency(g)
        assert adj["aws_vpc.main"] == []

    def test_deps_as_sorted_list(self):
        resources = [
            make_resource("aws_vpc.main"),
            make_resource("aws_security_group.sg"),
            make_resource(
                "aws_instance.web",
                dependencies=["aws_vpc.main", "aws_security_group.sg"],
            ),
        ]
        g = build(make_state(resources))
        adj = to_adjacency(g)
        assert adj["aws_instance.web"] == sorted(
            ["aws_vpc.main", "aws_security_group.sg"]
        )

    def test_json_serialisable(self):
        import json

        resources = [
            make_resource("aws_vpc.main"),
            make_resource("aws_instance.web", dependencies=["aws_vpc.main"]),
        ]
        g = build(make_state(resources))
        # Must not raise
        json.dumps(to_adjacency(g))


# ---------------------------------------------------------------------------
# TestBuildWithFixtures
# ---------------------------------------------------------------------------


class TestBuildWithFixtures:
    """Integration tests using real fixture files."""

    def test_simple_fixture_builds_graph(self):
        state = StateParser().parse(load_fixture("simple_v4.tfstate"))
        g = build(state)
        assert isinstance(g, DependencyGraph)
        assert g.node_count > 0

    def test_simple_fixture_node_count(self):
        # simple_v4 has 2 managed resources + 1 data source = 3 nodes
        state = StateParser().parse(load_fixture("simple_v4.tfstate"))
        g = build(state)
        assert g.node_count == 3

    def test_simple_fixture_has_edges(self):
        # aws_instance.web depends on aws_security_group.main and aws_subnet.public
        state = StateParser().parse(load_fixture("simple_v4.tfstate"))
        g = build(state)
        assert g.edge_count >= 1

    def test_modules_fixture_builds_graph(self):
        state = StateParser().parse(load_fixture("with_modules.tfstate"))
        g = build(state)
        assert g.node_count == 3

    def test_modules_fixture_dependencies_resolved(self):
        # aws_subnet.public depends on aws_vpc.main
        state = StateParser().parse(load_fixture("with_modules.tfstate"))
        g = build(state)
        subnet_addr = "module.vpc.aws_subnet.public"
        vpc_addr = "module.vpc.aws_vpc.main"
        assert vpc_addr in g.adjacency.get(subnet_addr, set())

    def test_to_dot_does_not_raise_on_fixtures(self):
        for fixture in ["simple_v4.tfstate", "with_modules.tfstate"]:
            state = StateParser().parse(load_fixture(fixture))
            g = build(state)
            output = to_dot(g)
            assert isinstance(output, str)

    def test_orphans_does_not_raise(self):
        state = StateParser().parse(load_fixture("simple_v4.tfstate"))
        g = build(state)
        result = orphans(g)
        assert isinstance(result, list)

    def test_cycles_empty_for_valid_state(self):
        # A valid Terraform state must never contain cycles
        for fixture in ["simple_v4.tfstate", "with_modules.tfstate"]:
            state = StateParser().parse(load_fixture(fixture))
            g = build(state)
            assert cycles(g) == []
