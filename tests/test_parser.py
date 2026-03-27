"""
Unit tests for parser.py

Run with:
    python -m pytest tests/test_parser.py -v

Test structure
--------------
    TestExtractProvider       — unit tests for the _extract_provider() helper
    TestParseResource         — unit tests for the _parse_resource() helper
    TestTFResourceAddress     — unit tests for TFResource.address / short_address
    TestStateParserSimple     — integration tests using the simple_v4.tfstate fixture
    TestStateParserWithModules — integration tests using the with_modules.tfstate fixture
    TestStateParserErrors     — error handling: missing file, bad JSON, wrong format
"""

import json
import tempfile
from pathlib import Path

import pytest

from parser import (
    ParsedState,
    StateParser,
    TFOutput,
    TFResource,
    _extract_provider,
    _parse_resource,
)

# Path to the fixtures directory, relative to this test file
FIXTURES = Path(__file__).parent / "fixtures"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def load_fixture(name: str) -> str:
    """Returns the absolute path to a fixture file as a string."""
    return str(FIXTURES / name)


# ---------------------------------------------------------------------------
# _extract_provider
# ---------------------------------------------------------------------------

class TestExtractProvider:
    """
    Tests for the _extract_provider() helper.

    Covers the modern registry format (Terraform >= 0.13), third-party
    providers, the legacy dot-notation format, and unknown inputs.
    """

    def test_registry_format(self):
        # Standard HashiCorp provider in registry format
        raw = 'provider["registry.terraform.io/hashicorp/aws"]'
        assert _extract_provider(raw) == "aws"

    def test_google_provider(self):
        # Google Cloud provider
        raw = 'provider["registry.terraform.io/hashicorp/google"]'
        assert _extract_provider(raw) == "google"

    def test_azure_provider(self):
        # Azure provider (note the "rm" suffix)
        raw = 'provider["registry.terraform.io/hashicorp/azurerm"]'
        assert _extract_provider(raw) == "azurerm"

    def test_third_party_provider(self):
        # Third-party provider with a different namespace
        raw = 'provider["registry.terraform.io/datadog/datadog"]'
        assert _extract_provider(raw) == "datadog"

    def test_legacy_format(self):
        # Terraform < 0.13 used dot-notation
        assert _extract_provider("provider.aws") == "aws"

    def test_unknown_format_returns_truncated(self):
        # Unknown format should not raise — returns a truncated string
        result = _extract_provider("something_weird")
        assert len(result) <= 40


# ---------------------------------------------------------------------------
# _parse_resource
# ---------------------------------------------------------------------------

class TestParseResource:
    """
    Tests for the _parse_resource() internal helper.

    Uses a factory method (_make_raw) to build minimal valid resource blocks
    and override specific fields per test case.
    """

    def _make_raw(self, **kwargs) -> dict:
        """
        Returns a minimal valid raw resource block.
        Any keyword argument overrides the corresponding top-level key.
        """
        base = {
            "mode": "managed",
            "type": "aws_instance",
            "name": "web",
            "provider": 'provider["registry.terraform.io/hashicorp/aws"]',
            "instances": [
                {
                    "attributes": {"id": "i-123", "instance_type": "t3.micro"},
                    "dependencies": ["aws_security_group.main"],
                }
            ],
        }
        base.update(kwargs)
        return base

    def test_basic_parsing(self):
        # A standard managed resource should parse into a single TFResource
        resources = _parse_resource(self._make_raw(), [])
        assert len(resources) == 1
        r = resources[0]
        assert r.type == "aws_instance"
        assert r.name == "web"
        assert r.provider == "aws"
        assert r.mode == "managed"
        assert r.module is None  # root-level resource has no module

    def test_attributes_preserved(self):
        # All instance attributes must be preserved as-is
        r = _parse_resource(self._make_raw(), [])[0]
        assert r.attributes["id"] == "i-123"
        assert r.attributes["instance_type"] == "t3.micro"

    def test_dependencies_preserved(self):
        # The dependency list must be carried over unchanged
        r = _parse_resource(self._make_raw(), [])[0]
        assert "aws_security_group.main" in r.dependencies

    def test_module_extracted(self):
        # Resources inside a module must expose the module path
        raw = self._make_raw(module="module.vpc")
        r = _parse_resource(raw, [])[0]
        assert r.module == "module.vpc"

    def test_data_source_mode(self):
        # Data sources have mode == "data"
        raw = self._make_raw(mode="data", type="aws_ami", name="ubuntu")
        r = _parse_resource(raw, [])[0]
        assert r.mode == "data"

    def test_no_instances_adds_warning(self):
        # A resource block with an empty instances list should be skipped
        # and a warning should be appended
        raw = self._make_raw(instances=[])
        warnings = []
        resources = _parse_resource(raw, warnings)
        assert resources == []
        assert len(warnings) == 1
        assert "no instances" in warnings[0].lower()

    def test_multiple_instances_indexed(self):
        # When count > 1, each instance gets an index suffix
        raw = self._make_raw(instances=[
            {"attributes": {"id": "i-001"}, "dependencies": []},
            {"attributes": {"id": "i-002"}, "dependencies": []},
        ])
        resources = _parse_resource(raw, [])
        assert len(resources) == 2
        assert resources[0].name == "web[0]"
        assert resources[1].name == "web[1]"

    def test_empty_attributes_ok(self):
        # A null attributes field should be normalized to an empty dict
        raw = self._make_raw(instances=[{"attributes": None, "dependencies": []}])
        r = _parse_resource(raw, [])[0]
        assert r.attributes == {}


# ---------------------------------------------------------------------------
# TFResource.address and short_address
# ---------------------------------------------------------------------------

class TestTFResourceAddress:
    """
    Tests for the TFResource.address and TFResource.short_address properties.

    Covers root-level resources, module-scoped resources, and data sources.
    """

    def _resource(self, **kwargs) -> TFResource:
        """
        Returns a minimal TFResource with sensible defaults.
        Any keyword argument overrides the corresponding field.
        """
        defaults = dict(
            type="aws_instance", name="web", provider="aws",
            mode="managed", module=None, attributes={},
            dependencies=[], raw={},
        )
        defaults.update(kwargs)
        return TFResource(**defaults)

    def test_simple_address(self):
        # Root-level managed resource
        assert self._resource().address == "aws_instance.web"

    def test_address_with_module(self):
        # Module-scoped resource includes the module prefix
        r = self._resource(module="module.vpc")
        assert r.address == "module.vpc.aws_instance.web"

    def test_data_source_address(self):
        # Data sources are prefixed with "data."
        r = self._resource(mode="data", type="aws_ami", name="ubuntu")
        assert r.address == "data.aws_ami.ubuntu"

    def test_data_source_address_with_module(self):
        # Module-scoped data source combines both prefixes
        r = self._resource(mode="data", type="aws_ami", name="ubuntu", module="module.app")
        assert r.address == "module.app.data.aws_ami.ubuntu"

    def test_short_address_no_module(self):
        # short_address equals address when resource is at the root
        assert self._resource().short_address == "aws_instance.web"

    def test_short_address_ignores_module(self):
        # short_address always strips the module prefix
        r = self._resource(module="module.vpc")
        assert r.short_address == "aws_instance.web"


# ---------------------------------------------------------------------------
# StateParser — simple fixture (simple_v4.tfstate)
# ---------------------------------------------------------------------------

class TestStateParserSimple:
    """
    Integration tests using simple_v4.tfstate.

    That fixture contains:
    - 2 managed resources: aws_instance.web, aws_security_group.main
    - 1 data source: data.aws_ami.ubuntu
    - 2 outputs: db_password (sensitive), app_url (non-sensitive)
    """

    @pytest.fixture
    def state(self) -> ParsedState:
        """Parses the simple_v4 fixture once and shares it across tests."""
        return StateParser().parse(load_fixture("simple_v4.tfstate"))

    def test_returns_parsed_state(self, state):
        assert isinstance(state, ParsedState)

    def test_terraform_version(self, state):
        assert state.terraform_version == "1.5.3"

    def test_serial(self, state):
        assert state.serial == 12

    def test_resources_count(self, state):
        # Only managed resources, not data sources
        assert len(state.resources) == 2

    def test_data_sources_count(self, state):
        assert len(state.data_sources) == 1

    def test_resource_types(self, state):
        types = {r.type for r in state.resources}
        assert types == {"aws_instance", "aws_security_group"}

    def test_data_source_type(self, state):
        assert state.data_sources[0].type == "aws_ami"

    def test_outputs_count(self, state):
        assert len(state.outputs) == 2

    def test_sensitive_output(self, state):
        # db_password is marked sensitive in the fixture
        sensitive = [o for o in state.outputs if o.sensitive]
        assert len(sensitive) == 1
        assert sensitive[0].name == "db_password"

    def test_non_sensitive_output(self, state):
        # app_url is not sensitive
        non_sensitive = [o for o in state.outputs if not o.sensitive]
        assert len(non_sensitive) == 1
        assert non_sensitive[0].name == "app_url"

    def test_no_warnings(self, state):
        # A well-formed v4 state should produce no warnings
        assert state.warnings == []

    def test_by_type(self, state):
        instances = state.by_type("aws_instance")
        assert len(instances) == 1
        assert instances[0].name == "web"

    def test_by_provider(self, state):
        # Both managed resources belong to the aws provider
        aws_resources = state.by_provider("aws")
        assert len(aws_resources) == 2

    def test_dependencies_preserved(self, state):
        instance = state.by_type("aws_instance")[0]
        assert "aws_security_group.main" in instance.dependencies


# ---------------------------------------------------------------------------
# StateParser — module fixture (with_modules.tfstate)
# ---------------------------------------------------------------------------

class TestStateParserWithModules:
    """
    Integration tests using with_modules.tfstate.

    That fixture contains resources inside two modules (module.vpc, module.app)
    and no root-level resources.
    """

    @pytest.fixture
    def state(self) -> ParsedState:
        """Parses the with_modules fixture once and shares it across tests."""
        return StateParser().parse(load_fixture("with_modules.tfstate"))

    def test_resources_count(self, state):
        assert len(state.resources) == 3

    def test_modules_extracted(self, state):
        # Both modules must be present; no root-level (None) resources
        modules = {r.module for r in state.resources}
        assert modules == {"module.vpc", "module.app"}

    def test_by_module(self, state):
        # module.vpc contains aws_vpc.main and aws_subnet.public
        vpc_resources = state.by_module("module.vpc")
        assert len(vpc_resources) == 2

    def test_address_includes_module(self, state):
        vpc = state.by_module("module.vpc")
        addresses = {r.address for r in vpc}
        assert "module.vpc.aws_vpc.main" in addresses

    def test_no_root_resources(self, state):
        # This fixture has no root-level resources
        root = [r for r in state.resources if r.module is None]
        assert root == []


# ---------------------------------------------------------------------------
# StateParser — error handling
# ---------------------------------------------------------------------------

class TestStateParserErrors:
    """
    Tests for error handling in StateParser.parse().

    Covers missing files, invalid JSON, wrong top-level type, unsupported
    format versions, and edge cases like an empty resources list.
    """

    def test_file_not_found(self):
        # Parsing a non-existent file must raise FileNotFoundError
        with pytest.raises(FileNotFoundError):
            StateParser().parse("/nonexistent/path/terraform.tfstate")

    def test_invalid_json(self):
        # A file that is not valid JSON must raise ValueError
        with tempfile.NamedTemporaryFile(suffix=".tfstate", mode="w", delete=False) as f:
            f.write("this is not json {{{")
            path = f.name
        with pytest.raises(ValueError, match="Invalid JSON"):
            StateParser().parse(path)

    def test_json_array_not_object(self):
        # A JSON array at the top level is not a valid tfstate
        with tempfile.NamedTemporaryFile(suffix=".tfstate", mode="w", delete=False) as f:
            json.dump([], f)
            path = f.name
        with pytest.raises(ValueError, match="JSON object"):
            StateParser().parse(path)

    def test_unsupported_version_adds_warning(self):
        # Version 3 is not fully supported — a warning must be emitted
        # but parsing should not raise an exception
        data = {
            "version": 3,
            "terraform_version": "0.12.0",
            "serial": 1,
            "lineage": "x",
            "outputs": {},
            "resources": [],
        }
        with tempfile.NamedTemporaryFile(suffix=".tfstate", mode="w", delete=False) as f:
            json.dump(data, f)
            path = f.name
        state = StateParser().parse(path)
        assert any("not fully supported" in w for w in state.warnings)

    def test_empty_resources_ok(self):
        # An empty resources list is valid (e.g. freshly initialized workspace)
        data = {
            "version": 4,
            "terraform_version": "1.5.0",
            "serial": 1,
            "lineage": "x",
            "outputs": {},
            "resources": [],
        }
        with tempfile.NamedTemporaryFile(suffix=".tfstate", mode="w", delete=False) as f:
            json.dump(data, f)
            path = f.name
        state = StateParser().parse(path)
        assert state.resources == []
        assert state.data_sources == []
