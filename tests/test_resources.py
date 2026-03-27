"""
Unit tests for resources.py

Run with:
    python -m pytest tests/test_resources.py -v

Test structure
--------------
    TestGroupByProvider    — unit tests for group_by_provider()
    TestGroupByType        — unit tests for group_by_type()
    TestGroupByModule      — unit tests for group_by_module()
    TestFilterResources    — unit tests for filter_resources()
    TestSummary            — unit tests for summary()
    TestFormatResource     — unit tests for format_resource()
    TestFormatSummary      — unit tests for format_summary()
"""

from pathlib import Path

import pytest

from parser import ParsedState, StateParser, TFResource
from resources import (
    ResourceSummary,
    filter_resources,
    format_resource,
    format_summary,
    group_by_module,
    group_by_provider,
    group_by_type,
    summary,
)

FIXTURES = Path(__file__).parent / "fixtures"


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------


def load_fixture(name: str) -> str:
    """Returns the absolute path to a fixture file as a string."""
    return str(FIXTURES / name)


@pytest.fixture
def simple_state() -> ParsedState:
    """
    ParsedState from simple_v4.tfstate.
    Contains: aws_instance.web, aws_security_group.main, data.aws_ami.ubuntu.
    All resources at root level, no modules.
    """
    return StateParser().parse(load_fixture("simple_v4.tfstate"))


@pytest.fixture
def module_state() -> ParsedState:
    """
    ParsedState from with_modules.tfstate.
    Contains: module.vpc (aws_vpc.main, aws_subnet.public), module.app (aws_instance.server).
    No root-level resources.
    """
    return StateParser().parse(load_fixture("with_modules.tfstate"))


# ---------------------------------------------------------------------------
# group_by_provider
# ---------------------------------------------------------------------------


class TestGroupByProvider:
    """Tests for group_by_provider() — groups managed resources by provider."""

    def test_returns_dict(self, simple_state):
        result = group_by_provider(simple_state)
        assert isinstance(result, dict)

    def test_single_provider(self, simple_state):
        # simple_v4 only has AWS resources
        result = group_by_provider(simple_state)
        assert list(result.keys()) == ["aws"]

    def test_correct_resource_count(self, simple_state):
        # 2 managed resources (aws_instance + aws_security_group), data source excluded
        result = group_by_provider(simple_state)
        assert len(result["aws"]) == 2

    def test_data_sources_excluded(self, simple_state):
        # data.aws_ami.ubuntu must not appear in group_by_provider output
        result = group_by_provider(simple_state)
        all_resources = [r for resources in result.values() for r in resources]
        assert all(r.mode == "managed" for r in all_resources)

    def test_keys_sorted_alphabetically(self, module_state):
        # All resources are aws in this fixture, but keys must be sorted
        result = group_by_provider(module_state)
        keys = list(result.keys())
        assert keys == sorted(keys)

    def test_resources_correctly_assigned(self, simple_state):
        # Each resource must land in the bucket matching its provider
        result = group_by_provider(simple_state)
        for provider, resources in result.items():
            for r in resources:
                assert r.provider == provider

    def test_empty_state_returns_empty_dict(self):
        # A state with no resources should return an empty dict
        empty = ParsedState(
            terraform_version="1.5.0",
            serial=1,
            lineage="x",
            resources=[],
            data_sources=[],
            outputs=[],
            warnings=[],
        )
        assert group_by_provider(empty) == {}


# ---------------------------------------------------------------------------
# group_by_type
# ---------------------------------------------------------------------------


class TestGroupByType:
    """Tests for group_by_type() — groups managed resources by resource type."""

    def test_returns_dict(self, simple_state):
        result = group_by_type(simple_state)
        assert isinstance(result, dict)

    def test_correct_types_present(self, simple_state):
        result = group_by_type(simple_state)
        assert "aws_instance" in result
        assert "aws_security_group" in result

    def test_data_sources_excluded(self, simple_state):
        # aws_ami is a data source — must not appear as a type key
        result = group_by_type(simple_state)
        assert "aws_ami" not in result

    def test_each_type_has_correct_resources(self, simple_state):
        result = group_by_type(simple_state)
        assert len(result["aws_instance"]) == 1
        assert result["aws_instance"][0].name == "web"

    def test_keys_sorted_alphabetically(self, simple_state):
        result = group_by_type(simple_state)
        keys = list(result.keys())
        assert keys == sorted(keys)

    def test_resources_correctly_assigned(self, simple_state):
        result = group_by_type(simple_state)
        for res_type, resources in result.items():
            for r in resources:
                assert r.type == res_type


# ---------------------------------------------------------------------------
# group_by_module
# ---------------------------------------------------------------------------


class TestGroupByModule:
    """Tests for group_by_module() — groups all resources by module path."""

    def test_root_resources_under_none_key(self, simple_state):
        # simple_v4 has no modules — all resources go under None
        result = group_by_module(simple_state)
        assert None in result

    def test_includes_data_sources(self, simple_state):
        # data.aws_ami.ubuntu must be included (group_by_module uses all_resources)
        result = group_by_module(simple_state)
        all_resources = [r for resources in result.values() for r in resources]
        data_sources = [r for r in all_resources if r.mode == "data"]
        assert len(data_sources) == 1

    def test_module_keys_present(self, module_state):
        result = group_by_module(module_state)
        assert "module.vpc" in result
        assert "module.app" in result

    def test_no_root_in_module_fixture(self, module_state):
        # with_modules.tfstate has no root-level resources
        result = group_by_module(module_state)
        assert None not in result

    def test_correct_resource_count_per_module(self, module_state):
        result = group_by_module(module_state)
        # module.vpc has aws_vpc.main + aws_subnet.public
        assert len(result["module.vpc"]) == 2
        # module.app has aws_instance.server
        assert len(result["module.app"]) == 1

    def test_none_key_comes_last(self, simple_state):
        # None (root) must always be the last key
        result = group_by_module(simple_state)
        keys = list(result.keys())
        if None in keys:
            assert keys[-1] is None


# ---------------------------------------------------------------------------
# filter_resources
# ---------------------------------------------------------------------------


class TestFilterResources:
    """Tests for filter_resources() — filters managed resources by criteria."""

    def test_no_filters_returns_all(self, simple_state):
        # With no filters, all managed resources are returned
        result = filter_resources(simple_state)
        assert len(result) == len(simple_state.resources)

    def test_filter_by_provider(self, simple_state):
        result = filter_resources(simple_state, provider="aws")
        assert len(result) == 2
        assert all(r.provider == "aws" for r in result)

    def test_filter_by_provider_no_match(self, simple_state):
        result = filter_resources(simple_state, provider="google")
        assert result == []

    def test_filter_by_type(self, simple_state):
        result = filter_resources(simple_state, resource_type="aws_instance")
        assert len(result) == 1
        assert result[0].name == "web"

    def test_filter_by_module(self, module_state):
        result = filter_resources(module_state, module="module.vpc")
        assert len(result) == 2
        assert all(r.module == "module.vpc" for r in result)

    def test_filter_by_empty_string_matches_root(self, simple_state):
        # Empty string "" should match root-level resources (module == None)
        result = filter_resources(simple_state, module="")
        assert len(result) == 2  # both managed resources are at root

    def test_filter_by_name_contains(self, simple_state):
        result = filter_resources(simple_state, name_contains="web")
        assert len(result) == 1
        assert result[0].name == "web"

    def test_filter_by_name_contains_case_insensitive(self, simple_state):
        # Name matching must be case-insensitive
        result = filter_resources(simple_state, name_contains="WEB")
        assert len(result) == 1

    def test_combined_filters(self, module_state):
        # provider=aws AND module=module.vpc should return 2 resources
        result = filter_resources(
            module_state, provider="aws", module="module.vpc"
        )
        assert len(result) == 2

    def test_combined_filters_no_match(self, module_state):
        # provider=google AND module=module.vpc — no match
        result = filter_resources(
            module_state, provider="google", module="module.vpc"
        )
        assert result == []


# ---------------------------------------------------------------------------
# summary
# ---------------------------------------------------------------------------


class TestSummary:
    """Tests for summary() — computes high-level counts from a parsed state."""

    def test_returns_resource_summary(self, simple_state):
        result = summary(simple_state)
        assert isinstance(result, ResourceSummary)

    def test_total_resources(self, simple_state):
        result = summary(simple_state)
        assert result.total_resources == 2

    def test_total_data_sources(self, simple_state):
        result = summary(simple_state)
        assert result.total_data_sources == 1

    def test_providers_set(self, simple_state):
        result = summary(simple_state)
        assert result.providers == {"aws"}

    def test_resource_types_set(self, simple_state):
        result = summary(simple_state)
        assert result.resource_types == {"aws_instance", "aws_security_group"}

    def test_modules_set_root_only(self, simple_state):
        # simple_v4 has no modules — only None in the modules set
        result = summary(simple_state)
        assert result.modules == {None}

    def test_modules_set_with_modules(self, module_state):
        result = summary(module_state)
        assert "module.vpc" in result.modules
        assert "module.app" in result.modules

    def test_counts_by_provider(self, simple_state):
        result = summary(simple_state)
        assert result.counts_by_provider == {"aws": 2}

    def test_counts_by_type(self, simple_state):
        result = summary(simple_state)
        assert result.counts_by_type["aws_instance"] == 1
        assert result.counts_by_type["aws_security_group"] == 1

    def test_counts_by_module(self, module_state):
        result = summary(module_state)
        assert result.counts_by_module["module.vpc"] == 2
        assert result.counts_by_module["module.app"] == 1

    def test_empty_state(self):
        empty = ParsedState(
            terraform_version="1.5.0",
            serial=1,
            lineage="x",
            resources=[],
            data_sources=[],
            outputs=[],
            warnings=[],
        )
        result = summary(empty)
        assert result.total_resources == 0
        assert result.total_data_sources == 0
        assert result.providers == set()


# ---------------------------------------------------------------------------
# format_resource
# ---------------------------------------------------------------------------


class TestFormatResource:
    """Tests for format_resource() — formats a TFResource as a string."""

    def _make_resource(self, **kwargs) -> TFResource:
        """Returns a minimal TFResource with sensible defaults."""
        defaults = dict(
            type="aws_instance",
            name="web",
            provider="aws",
            mode="managed",
            module=None,
            attributes={},
            dependencies=[],
            raw={},
        )
        defaults.update(kwargs)
        return TFResource(**defaults)

    def test_contains_type(self):
        r = self._make_resource()
        assert "aws_instance" in format_resource(r, color=False)

    def test_contains_name(self):
        r = self._make_resource()
        assert "web" in format_resource(r, color=False)

    def test_contains_provider(self):
        r = self._make_resource()
        assert "aws" in format_resource(r, color=False)

    def test_contains_module_when_present(self):
        r = self._make_resource(module="module.vpc")
        assert "module.vpc" in format_resource(r, color=False)

    def test_no_module_string_when_root(self):
        r = self._make_resource(module=None)
        output = format_resource(r, color=False)
        assert "module" not in output

    def test_color_false_has_no_ansi(self):
        r = self._make_resource()
        output = format_resource(r, color=False)
        # ANSI escape codes start with \033
        assert "\033" not in output

    def test_color_true_has_ansi(self):
        r = self._make_resource()
        output = format_resource(r, color=True)
        assert "\033" in output


# ---------------------------------------------------------------------------
# format_summary
# ---------------------------------------------------------------------------


class TestFormatSummary:
    """Tests for format_summary() — formats a ResourceSummary as a string."""

    def test_contains_resource_count(self, simple_state):
        s = summary(simple_state)
        output = format_summary(s, color=False)
        assert "2" in output  # total_resources == 2

    def test_contains_provider_name(self, simple_state):
        s = summary(simple_state)
        output = format_summary(s, color=False)
        assert "aws" in output

    def test_contains_data_source_count(self, simple_state):
        s = summary(simple_state)
        output = format_summary(s, color=False)
        assert "1" in output  # total_data_sources == 1

    def test_contains_module_names(self, module_state):
        s = summary(module_state)
        output = format_summary(s, color=False)
        assert "module.vpc" in output
        assert "module.app" in output

    def test_root_label_when_no_modules(self, simple_state):
        s = summary(simple_state)
        output = format_summary(s, color=False)
        assert "root" in output

    def test_color_false_has_no_ansi(self, simple_state):
        s = summary(simple_state)
        output = format_summary(s, color=False)
        assert "\033" not in output

    def test_color_true_has_ansi(self, simple_state):
        s = summary(simple_state)
        output = format_summary(s, color=True)
        assert "\033" in output

    def test_multiline_output(self, simple_state):
        s = summary(simple_state)
        output = format_summary(s, color=False)
        assert "\n" in output
