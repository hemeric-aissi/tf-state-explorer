"""
Unit tests for secrets.py

Run with:
    python -m pytest tests/test_secrets.py -v

Test structure
--------------
    TestSeverityEnum         — enum values and ordering
    TestFindingDataclass     — Finding fields and defaults
    TestScanAttributes       — _scan_attributes() internal helper
    TestScanOutputs          — _scan_outputs() internal helper
    TestScan                 — scan() public API end-to-end
    TestScanWithFixtures     — integration tests using real fixture files
    TestFormatFindings       — format_findings() output formatting
"""

from pathlib import Path


from parser import ParsedState, StateParser, TFOutput, TFResource
from secrets import (
    Finding,
    Severity,
    _scan_attributes,
    _scan_outputs,
    format_findings,
    scan,
)

FIXTURES = Path(__file__).parent / "fixtures"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def load_fixture(name: str) -> str:
    """Returns the absolute path to a fixture file as a string."""
    return str(FIXTURES / name)


def make_resource(attributes: dict, **kwargs) -> TFResource:
    """Returns a minimal TFResource with the given attributes."""
    defaults = dict(
        type="aws_instance",
        name="web",
        provider="aws",
        mode="managed",
        module=None,
        dependencies=[],
        raw={},
    )
    defaults.update(kwargs)
    return TFResource(attributes=attributes, **defaults)


def make_output(name: str, value: object, sensitive: bool = False) -> TFOutput:
    """Returns a TFOutput with the given name, value and sensitivity flag."""
    return TFOutput(name=name, value=value, sensitive=sensitive, type="string")


def make_state(
    resources: list[TFResource] | None = None,
    outputs: list[TFOutput] | None = None,
) -> ParsedState:
    """Returns a minimal ParsedState with the given resources and outputs."""
    return ParsedState(
        terraform_version="1.5.0",
        serial=1,
        lineage="x",
        resources=resources or [],
        data_sources=[],
        outputs=outputs or [],
        warnings=[],
    )


# ---------------------------------------------------------------------------
# TestSeverityEnum
# ---------------------------------------------------------------------------


class TestSeverityEnum:
    """Tests for the Severity enum."""

    def test_high_value(self):
        assert Severity.HIGH.value == "HIGH"

    def test_medium_value(self):
        assert Severity.MEDIUM.value == "MEDIUM"

    def test_low_value(self):
        assert Severity.LOW.value == "LOW"

    def test_three_levels(self):
        assert len(Severity) == 3


# ---------------------------------------------------------------------------
# TestFindingDataclass
# ---------------------------------------------------------------------------


class TestFindingDataclass:
    """Tests for the Finding dataclass."""

    def _make_finding(self, **kwargs) -> Finding:
        defaults = dict(
            address="aws_instance.web",
            attribute="password",
            value="s3cr3t",
            reason="test reason",
            severity=Severity.HIGH,
            source="resource",
        )
        defaults.update(kwargs)
        return Finding(**defaults)

    def test_fields_accessible(self):
        f = self._make_finding()
        assert f.address == "aws_instance.web"
        assert f.attribute == "password"
        assert f.value == "s3cr3t"
        assert f.reason == "test reason"
        assert f.severity == Severity.HIGH
        assert f.source == "resource"

    def test_severity_is_enum(self):
        f = self._make_finding(severity=Severity.MEDIUM)
        assert isinstance(f.severity, Severity)


# ---------------------------------------------------------------------------
# TestScanAttributes
# ---------------------------------------------------------------------------


class TestScanAttributes:
    """Tests for the _scan_attributes() internal helper."""

    def test_aws_access_key_pattern(self):
        # AKIA... value in an access_key attribute should trigger HIGH
        attrs = {"access_key": "AKIAIOSFODNN7EXAMPLE"}
        findings = _scan_attributes("aws_instance.web", attrs, "resource")
        assert len(findings) >= 1
        assert any(f.severity == Severity.HIGH for f in findings)

    def test_private_key_pem_value(self):
        # A PEM block in any attribute should trigger HIGH
        attrs = {
            "some_attr": "-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----"
        }
        findings = _scan_attributes("tls_private_key.cert", attrs, "resource")
        assert any(f.severity == Severity.HIGH for f in findings)

    def test_private_key_attribute_name(self):
        # Attribute named private_key should trigger HIGH regardless of value
        attrs = {"private_key": "some_value"}
        findings = _scan_attributes("aws_instance.web", attrs, "resource")
        assert any(f.severity == Severity.HIGH for f in findings)

    def test_password_attribute_medium(self):
        # Attribute named password should trigger MEDIUM
        attrs = {"password": "hunter2"}
        findings = _scan_attributes("aws_db_instance.main", attrs, "resource")
        assert any(f.severity == Severity.MEDIUM for f in findings)

    def test_token_attribute_medium(self):
        attrs = {"api_token": "tok_abc123"}
        findings = _scan_attributes("some_resource.x", attrs, "resource")
        assert any(f.severity == Severity.MEDIUM for f in findings)

    def test_database_url_medium(self):
        # Connection string with credentials should trigger MEDIUM
        attrs = {"connection_string": "postgresql://user:pass@db.internal/mydb"}
        findings = _scan_attributes("aws_db_instance.main", attrs, "resource")
        assert any(f.severity == Severity.MEDIUM for f in findings)

    def test_github_token_medium(self):
        attrs = {"token": "ghp_" + "A" * 36}
        findings = _scan_attributes("github_actions_secret.x", attrs, "resource")
        assert any(f.severity == Severity.MEDIUM for f in findings)

    def test_public_ip_low(self):
        # A public IP in a public_ip attribute should trigger LOW
        attrs = {"public_ip": "54.12.34.56"}
        findings = _scan_attributes("aws_instance.web", attrs, "resource")
        assert any(f.severity == Severity.LOW for f in findings)

    def test_arn_low(self):
        # An AWS ARN should trigger LOW
        attrs = {"arn": "arn:aws:iam::123456789012:role/MyRole"}
        findings = _scan_attributes("aws_iam_role.main", attrs, "resource")
        assert any(f.severity == Severity.LOW for f in findings)

    def test_non_string_values_skipped(self):
        # Integer, bool, dict, list attributes must not be scanned
        attrs = {
            "count": 3,
            "enabled": True,
            "tags": {"env": "prod"},
            "ports": [80, 443],
        }
        findings = _scan_attributes("aws_instance.web", attrs, "resource")
        assert findings == []

    def test_empty_string_skipped(self):
        attrs = {"password": ""}
        findings = _scan_attributes("aws_instance.web", attrs, "resource")
        assert findings == []

    def test_finding_address_correct(self):
        attrs = {"password": "secret"}
        findings = _scan_attributes(
            "module.app.aws_db_instance.main", attrs, "resource"
        )
        assert all(f.address == "module.app.aws_db_instance.main" for f in findings)

    def test_finding_source_correct(self):
        attrs = {"password": "secret"}
        findings = _scan_attributes("aws_instance.web", attrs, "data_source")
        assert all(f.source == "data_source" for f in findings)

    def test_value_truncated_at_120_chars(self):
        # Values longer than 120 chars must be truncated with "..."
        long_value = "x" * 200
        attrs = {"private_key": long_value}
        findings = _scan_attributes("aws_instance.web", attrs, "resource")
        if findings:
            assert len(findings[0].value) <= 124  # 120 + "..."

    def test_no_findings_for_safe_attributes(self):
        attrs = {
            "instance_type": "t3.micro",
            "ami": "ami-0abcdef1234567890",
            "region": "us-east-1",
        }
        findings = _scan_attributes("aws_instance.web", attrs, "resource")
        assert findings == []


# ---------------------------------------------------------------------------
# TestScanOutputs
# ---------------------------------------------------------------------------


class TestScanOutputs:
    """Tests for the _scan_outputs() internal helper."""

    def test_sensitive_output_always_flagged(self):
        # sensitive=True outputs must always produce a MEDIUM finding
        outputs = [make_output("db_password", "s3cr3t", sensitive=True)]
        findings = _scan_outputs(outputs)
        assert len(findings) == 1
        assert findings[0].severity == Severity.MEDIUM
        assert findings[0].source == "output"

    def test_sensitive_output_value_redacted(self):
        # The value in the finding must indicate the value is redacted
        outputs = [make_output("db_password", "s3cr3t", sensitive=True)]
        findings = _scan_outputs(outputs)
        assert (
            "redacted" in findings[0].value.lower()
            or "sensitive" in findings[0].value.lower()
        )

    def test_non_sensitive_output_scanned_by_rules(self):
        # Non-sensitive outputs are still scanned for suspicious values
        outputs = [make_output("api_token", "ghp_" + "A" * 36, sensitive=False)]
        findings = _scan_outputs(outputs)
        assert len(findings) >= 1

    def test_non_sensitive_safe_output_no_finding(self):
        outputs = [make_output("app_url", "https://myapp.example.com", sensitive=False)]
        findings = _scan_outputs(outputs)
        assert findings == []

    def test_non_string_output_value_skipped(self):
        outputs = [make_output("port", 8080, sensitive=False)]
        findings = _scan_outputs(outputs)
        assert findings == []

    def test_output_address_format(self):
        # Output address must be "output.<name>"
        outputs = [make_output("db_password", "x", sensitive=True)]
        findings = _scan_outputs(outputs)
        assert findings[0].address == "output.db_password"

    def test_multiple_outputs(self):
        outputs = [
            make_output("db_password", "secret", sensitive=True),
            make_output("app_url", "https://example.com", sensitive=False),
            make_output("api_key", "tok_abc123", sensitive=False),
        ]
        findings = _scan_outputs(outputs)
        # At least db_password (sensitive) must be flagged
        addresses = {f.address for f in findings}
        assert "output.db_password" in addresses


# ---------------------------------------------------------------------------
# TestScan
# ---------------------------------------------------------------------------


class TestScan:
    """Tests for the scan() public API."""

    def test_returns_list(self):
        state = make_state()
        assert isinstance(scan(state), list)

    def test_empty_state_no_findings(self):
        state = make_state()
        assert scan(state) == []

    def test_detects_high_severity(self):
        r = make_resource({"access_key": "AKIAIOSFODNN7EXAMPLE"})
        state = make_state(resources=[r])
        findings = scan(state)
        assert any(f.severity == Severity.HIGH for f in findings)

    def test_detects_sensitive_output(self):
        state = make_state(outputs=[make_output("db_pass", "x", sensitive=True)])
        findings = scan(state)
        assert any(f.source == "output" for f in findings)

    def test_min_severity_high_filters_medium_low(self):
        # With min_severity=HIGH, only HIGH findings should be returned
        r = make_resource(
            {
                "access_key": "AKIAIOSFODNN7EXAMPLE",  # HIGH
                "password": "hunter2",  # MEDIUM
                "public_ip": "54.12.34.56",  # LOW
            }
        )
        state = make_state(resources=[r])
        findings = scan(state, min_severity=Severity.HIGH)
        assert all(f.severity == Severity.HIGH for f in findings)

    def test_min_severity_medium_filters_low(self):
        r = make_resource(
            {
                "password": "hunter2",  # MEDIUM
                "public_ip": "54.12.34.56",  # LOW
            }
        )
        state = make_state(resources=[r])
        findings = scan(state, min_severity=Severity.MEDIUM)
        assert all(f.severity in (Severity.HIGH, Severity.MEDIUM) for f in findings)

    def test_min_severity_low_includes_all(self):
        r = make_resource(
            {
                "access_key": "AKIAIOSFODNN7EXAMPLE",
                "password": "secret",
                "public_ip": "54.12.34.56",
            }
        )
        state = make_state(resources=[r])
        findings = scan(state, min_severity=Severity.LOW)
        severities = {f.severity for f in findings}
        assert Severity.HIGH in severities

    def test_data_sources_excluded_by_default(self):
        # Data sources should NOT be scanned unless include_data_sources=True
        ds = TFResource(
            type="aws_secretsmanager_secret",
            name="db",
            provider="aws",
            mode="data",
            module=None,
            attributes={"password": "secret"},
            dependencies=[],
            raw={},
        )
        state = ParsedState(
            terraform_version="1.5.0",
            serial=1,
            lineage="x",
            resources=[],
            data_sources=[ds],
            outputs=[],
            warnings=[],
        )
        findings = scan(state)
        assert all(f.source != "data_source" for f in findings)

    def test_data_sources_included_when_flag_set(self):
        ds = TFResource(
            type="aws_secretsmanager_secret",
            name="db",
            provider="aws",
            mode="data",
            module=None,
            attributes={"password": "secret"},
            dependencies=[],
            raw={},
        )
        state = ParsedState(
            terraform_version="1.5.0",
            serial=1,
            lineage="x",
            resources=[],
            data_sources=[ds],
            outputs=[],
            warnings=[],
        )
        findings = scan(state, include_data_sources=True)
        assert any(f.source == "data_source" for f in findings)

    def test_findings_sorted_by_severity_then_address(self):
        r1 = make_resource({"password": "x"}, name="z_resource")
        r2 = make_resource({"access_key": "AKIAIOSFODNN7EXAMPLE"}, name="a_resource")
        state = make_state(resources=[r1, r2])
        findings = scan(state)
        severity_order = {Severity.HIGH: 0, Severity.MEDIUM: 1, Severity.LOW: 2}
        orders = [severity_order[f.severity] for f in findings]
        assert orders == sorted(orders)

    def test_finding_contains_correct_address(self):
        r = make_resource({"password": "secret"}, name="main", type="aws_db_instance")
        state = make_state(resources=[r])
        findings = scan(state)
        assert any(f.address == "aws_db_instance.main" for f in findings)


# ---------------------------------------------------------------------------
# TestScanWithFixtures
# ---------------------------------------------------------------------------


class TestScanWithFixtures:
    """Integration tests using real fixture files."""

    def test_simple_fixture_sensitive_output_detected(self):
        # simple_v4.tfstate has a sensitive output: db_password
        state = StateParser().parse(load_fixture("simple_v4.tfstate"))
        findings = scan(state)
        output_findings = [f for f in findings if f.source == "output"]
        assert any("db_password" in f.address for f in output_findings)

    def test_modules_fixture_no_crash(self):
        # with_modules.tfstate contains an aws_access_key attribute
        state = StateParser().parse(load_fixture("with_modules.tfstate"))
        findings = scan(state)
        # Should find the AKIAIOSFODNN7EXAMPLE key in module.app.aws_instance.server
        assert any(f.severity == Severity.HIGH for f in findings)

    def test_modules_fixture_aws_key_detected(self):
        state = StateParser().parse(load_fixture("with_modules.tfstate"))
        findings = scan(state)
        high_findings = [f for f in findings if f.severity == Severity.HIGH]
        assert any("aws_access_key" in f.attribute for f in high_findings)

    def test_scan_returns_list_for_any_state(self):
        # scan() must never raise — it always returns a list
        for fixture in ["simple_v4.tfstate", "with_modules.tfstate"]:
            state = StateParser().parse(load_fixture(fixture))
            result = scan(state)
            assert isinstance(result, list)


# ---------------------------------------------------------------------------
# TestFormatFindings
# ---------------------------------------------------------------------------


class TestFormatFindings:
    """Tests for format_findings() output formatting."""

    def _make_finding(self, severity: Severity = Severity.HIGH) -> Finding:
        return Finding(
            address="aws_instance.web",
            attribute="password",
            value="s3cr3t",
            reason="Test reason",
            severity=severity,
            source="resource",
        )

    def test_empty_findings_returns_no_findings_message(self):
        output = format_findings([], color=False)
        assert "no sensitive" in output.lower()

    def test_contains_address(self):
        output = format_findings([self._make_finding()], color=False)
        assert "aws_instance.web" in output

    def test_contains_attribute(self):
        output = format_findings([self._make_finding()], color=False)
        assert "password" in output

    def test_contains_severity(self):
        output = format_findings([self._make_finding(Severity.HIGH)], color=False)
        assert "HIGH" in output

    def test_contains_reason(self):
        output = format_findings([self._make_finding()], color=False)
        assert "Test reason" in output

    def test_contains_summary_line(self):
        findings = [
            self._make_finding(Severity.HIGH),
            self._make_finding(Severity.MEDIUM),
            self._make_finding(Severity.LOW),
        ]
        output = format_findings(findings, color=False)
        assert "Summary" in output
        assert "1 HIGH" in output
        assert "1 MEDIUM" in output
        assert "1 LOW" in output

    def test_color_false_no_ansi(self):
        output = format_findings([self._make_finding()], color=False)
        assert "\033" not in output

    def test_color_true_has_ansi(self):
        output = format_findings([self._make_finding()], color=True)
        assert "\033" in output

    def test_multiple_findings_all_present(self):
        findings = [
            Finding("res.a", "password", "x", "reason", Severity.HIGH, "resource"),
            Finding("res.b", "token", "y", "reason", Severity.MEDIUM, "resource"),
        ]
        output = format_findings(findings, color=False)
        assert "res.a" in output
        assert "res.b" in output
