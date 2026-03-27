"""
tf-state-explorer — secrets.py

Scans a parsed Terraform state for potentially sensitive values exposed in
resource attributes and outputs.

The detection is pattern-based: each rule matches attribute names or values
against a list of known sensitive patterns (access keys, passwords, tokens,
IP addresses, ARNs, private keys, ...).  False positives are possible — the
goal is to surface candidates for human review, not to make definitive claims.

Public API
----------
    from secrets import scan, Finding, Severity

    state    = StateParser().parse("terraform.tfstate")
    findings = scan(state)

    for f in findings:
        print(f.severity.value, f.address, f.attribute, f.reason)
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum

from parser import ParsedState, TFOutput


# ---------------------------------------------------------------------------
# Severity levels
# ---------------------------------------------------------------------------


class Severity(Enum):
    """
    Severity level assigned to a finding.

    HIGH   — almost certainly a real secret (AWS access key, private key, ...)
    MEDIUM — likely sensitive but needs human confirmation (password field, token, ...)
    LOW    — potentially sensitive context (IP address, ARN, internal hostname, ...)
    """

    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


# ---------------------------------------------------------------------------
# Finding dataclass
# ---------------------------------------------------------------------------


@dataclass
class Finding:
    """
    A single potentially sensitive value detected in the state.

    Attributes:
        address:    Full Terraform address of the resource or output, e.g.
                    "aws_instance.web" or "output.db_password".
        attribute:  Name of the attribute or output that triggered the rule,
                    e.g. "private_key", "password", "db_password".
        value:      The raw value that matched.  Truncated to 120 characters
                    to avoid flooding the output with large values.
        reason:     Human-readable explanation of why this was flagged.
        severity:   HIGH / MEDIUM / LOW — see Severity enum.
        source:     "resource", "data_source", or "output".
    """

    address: str
    attribute: str
    value: str
    reason: str
    severity: Severity
    source: str


# ---------------------------------------------------------------------------
# Detection rules
# ---------------------------------------------------------------------------

# Each rule is a tuple of:
#   (rule_id, severity, reason, key_pattern, value_pattern)
#
# key_pattern   — compiled regex matched against the attribute name (case-insensitive)
# value_pattern — compiled regex matched against the string value, or None to
#                 match on key name only
#
# A finding is raised when key_pattern matches AND (value_pattern is None OR
# value_pattern matches the value).

_RULES: list[tuple[str, Severity, str, re.Pattern, re.Pattern | None]] = [
    # -----------------------------------------------------------------------
    # HIGH — strongly indicative of a real secret
    # -----------------------------------------------------------------------
    (
        "AWS_ACCESS_KEY",
        Severity.HIGH,
        "AWS access key ID pattern detected",
        re.compile(r"access_key|aws_access_key_id", re.IGNORECASE),
        re.compile(r"AKIA[0-9A-Z]{16}", re.IGNORECASE),
    ),
    (
        "AWS_SECRET_KEY",
        Severity.HIGH,
        "AWS secret access key — attribute name suggests a credential",
        re.compile(
            r"secret_key|aws_secret_access_key|secret_access_key", re.IGNORECASE
        ),
        None,  # match on key name alone — value is often redacted
    ),
    (
        "PRIVATE_KEY",
        Severity.HIGH,
        "PEM private key block detected in attribute value",
        re.compile(r".", re.IGNORECASE),  # match any attribute name
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", re.IGNORECASE),
    ),
    (
        "PRIVATE_KEY_ATTR",
        Severity.HIGH,
        "Attribute name suggests a private key or certificate",
        re.compile(
            r"private_key|private_key_pem|client_key|tls_private_key", re.IGNORECASE
        ),
        None,
    ),
    (
        "GCP_SERVICE_ACCOUNT",
        Severity.HIGH,
        "GCP service account key JSON pattern detected",
        re.compile(r".", re.IGNORECASE),
        re.compile(r'"type"\s*:\s*"service_account"', re.IGNORECASE),
    ),
    # -----------------------------------------------------------------------
    # MEDIUM — likely sensitive, needs confirmation
    # -----------------------------------------------------------------------
    (
        "PASSWORD_ATTR",
        Severity.MEDIUM,
        "Attribute name contains 'password' — may expose a credential",
        re.compile(r"password|passwd|secret|credentials", re.IGNORECASE),
        None,
    ),
    (
        "TOKEN_ATTR",
        Severity.MEDIUM,
        "Attribute name contains 'token' — may expose an API token",
        re.compile(r"\btoken\b|api_token|auth_token|access_token", re.IGNORECASE),
        None,
    ),
    (
        "DATABASE_URL",
        Severity.MEDIUM,
        "Connection string with embedded credentials detected",
        re.compile(r".", re.IGNORECASE),
        re.compile(r"[a-zA-Z][a-zA-Z0-9+\-.]*://[^:]+:[^@]+@", re.IGNORECASE),
    ),
    (
        "GITHUB_TOKEN",
        Severity.MEDIUM,
        "GitHub personal access token pattern detected",
        re.compile(r".", re.IGNORECASE),
        re.compile(r"ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82}", re.IGNORECASE),
    ),
    (
        "SLACK_TOKEN",
        Severity.MEDIUM,
        "Slack API token pattern detected",
        re.compile(r".", re.IGNORECASE),
        re.compile(r"xox[baprs]-[0-9A-Za-z\-]+", re.IGNORECASE),
    ),
    (
        "SENSITIVE_OUTPUT",
        Severity.MEDIUM,
        "Terraform output is marked sensitive=true",
        re.compile(r".", re.IGNORECASE),
        None,  # handled separately in _scan_outputs
    ),
    # -----------------------------------------------------------------------
    # LOW — potentially sensitive context
    # -----------------------------------------------------------------------
    (
        "PUBLIC_IP",
        Severity.LOW,
        "Public IP address exposed in state — verify this is intentional",
        re.compile(r"public_ip|public_ipv4|external_ip|floating_ip", re.IGNORECASE),
        re.compile(
            r"\b(?!10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.)\d{1,3}(?:\.\d{1,3}){3}\b"
        ),
    ),
    (
        "ARN",
        Severity.LOW,
        "AWS ARN exposed in state — may reveal account IDs or resource paths",
        re.compile(r".", re.IGNORECASE),
        re.compile(r"arn:aws[a-z\-]*:[a-z0-9\-]+:[a-z0-9\-]*:\d{12}:", re.IGNORECASE),
    ),
    (
        "INTERNAL_HOSTNAME",
        Severity.LOW,
        "Internal hostname or endpoint exposed in state",
        re.compile(
            r"endpoint|hostname|host|internal_dns|private_dns|rds_endpoint",
            re.IGNORECASE,
        ),
        re.compile(r"\.(internal|local|corp|intranet)\b", re.IGNORECASE),
    ),
]


# ---------------------------------------------------------------------------
# Internal scanning helpers
# ---------------------------------------------------------------------------


def _truncate(value: str, max_len: int = 120) -> str:
    """Truncates a string to max_len characters, appending '...' if cut."""
    if len(value) <= max_len:
        return value
    return value[:max_len] + "..."


def _scan_attributes(
    address: str,
    attributes: dict,
    source: str,
) -> list[Finding]:
    """
    Scans a flat attribute dict for sensitive values.

    Iterates over all key/value pairs in the attributes dict and applies
    every rule.  Only string values are checked — non-string values (int,
    bool, dict, list) are skipped.

    Args:
        address:    Terraform address of the resource owning these attributes.
        attributes: Flat key/value attribute dict from a TFResource.
        source:     "resource" or "data_source" — used in the Finding.

    Returns:
        A list of Finding instances, one per matched rule per attribute.
    """
    findings: list[Finding] = []

    for attr_key, attr_value in attributes.items():
        # Only scan string values — other types don't contain secrets
        if not isinstance(attr_value, str):
            continue
        if not attr_value.strip():
            continue

        for rule_id, severity, reason, key_pattern, value_pattern in _RULES:
            # Skip the SENSITIVE_OUTPUT rule here — it's handled separately
            if rule_id == "SENSITIVE_OUTPUT":
                continue

            key_matches = key_pattern.search(attr_key)
            if not key_matches:
                continue

            if value_pattern is not None:
                if not value_pattern.search(attr_value):
                    continue

            findings.append(
                Finding(
                    address=address,
                    attribute=attr_key,
                    value=_truncate(attr_value),
                    reason=reason,
                    severity=severity,
                    source=source,
                )
            )
            # One finding per rule per attribute — stop checking this rule
            break

    return findings


def _scan_outputs(outputs: list[TFOutput]) -> list[Finding]:
    """
    Scans Terraform outputs for sensitive values.

    Outputs marked sensitive=True by Terraform are always flagged at MEDIUM.
    Non-sensitive outputs are scanned with the same attribute rules.

    Args:
        outputs: List of TFOutput instances from a ParsedState.

    Returns:
        A list of Finding instances for sensitive or suspicious outputs.
    """
    findings: list[Finding] = []

    for output in outputs:
        address = f"output.{output.name}"

        # Terraform-marked sensitive outputs are always flagged
        if output.sensitive:
            findings.append(
                Finding(
                    address=address,
                    attribute=output.name,
                    value="[sensitive — value redacted by Terraform]",
                    reason="Terraform output is marked sensitive=true",
                    severity=Severity.MEDIUM,
                    source="output",
                )
            )
            continue

        # Non-sensitive outputs: scan the value if it's a string
        if not isinstance(output.value, str) or not output.value.strip():
            continue

        for rule_id, severity, reason, key_pattern, value_pattern in _RULES:
            if rule_id == "SENSITIVE_OUTPUT":
                continue

            key_matches = key_pattern.search(output.name)
            if not key_matches:
                continue

            if value_pattern is not None:
                if not value_pattern.search(output.value):
                    continue

            findings.append(
                Finding(
                    address=address,
                    attribute=output.name,
                    value=_truncate(str(output.value)),
                    reason=reason,
                    severity=severity,
                    source="output",
                )
            )
            break

    return findings


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def scan(
    state: ParsedState,
    *,
    min_severity: Severity = Severity.LOW,
    include_data_sources: bool = False,
) -> list[Finding]:
    """
    Scans a parsed Terraform state for potentially sensitive values.

    Checks all managed resource attributes and outputs by default.
    Data sources are excluded by default because they are read-only and
    typically contain provider metadata rather than credentials.

    Findings are sorted by severity (HIGH first) then by address.

    Args:
        state:               A ParsedState returned by StateParser.parse().
        min_severity:        Minimum severity to include in results.
                             Defaults to LOW (include everything).
                             Pass Severity.MEDIUM to skip LOW findings.
                             Pass Severity.HIGH to only return confirmed secrets.
        include_data_sources: When True, also scans data source attributes.
                             Defaults to False.

    Returns:
        A sorted list of Finding instances.  Empty list if nothing is found.

    Example:
        state    = StateParser().parse("terraform.tfstate")
        findings = scan(state, min_severity=Severity.MEDIUM)

        for f in findings:
            print(f"[{f.severity.value}] {f.address} — {f.attribute}: {f.reason}")
    """
    findings: list[Finding] = []

    # Scan managed resources
    for resource in state.resources:
        findings.extend(
            _scan_attributes(resource.address, resource.attributes, "resource")
        )

    # Optionally scan data sources
    if include_data_sources:
        for ds in state.data_sources:
            findings.extend(_scan_attributes(ds.address, ds.attributes, "data_source"))

    # Always scan outputs
    findings.extend(_scan_outputs(state.outputs))

    # Apply severity filter
    severity_order = {Severity.HIGH: 0, Severity.MEDIUM: 1, Severity.LOW: 2}
    min_order = severity_order[min_severity]
    findings = [f for f in findings if severity_order[f.severity] <= min_order]

    # Sort: HIGH first, then MEDIUM, then LOW; alphabetically by address within each group
    findings.sort(key=lambda f: (severity_order[f.severity], f.address, f.attribute))

    return findings


def format_findings(findings: list[Finding], *, color: bool = True) -> str:
    """
    Formats a list of findings as a human-readable multi-line string.

    Each finding is rendered as a block with severity badge, address,
    attribute name, truncated value, and reason.

    Args:
        findings: List of Finding instances returned by scan().
        color:    When True, applies ANSI color codes. Set to False when
                  writing to a file or piping output.

    Returns:
        A formatted string, or a "no findings" message if the list is empty.
    """
    if not findings:
        msg = "No sensitive values detected."
        return f"\033[32m{msg}\033[0m" if color else msg

    _RESET = "\033[0m"
    _BOLD = "\033[1m"
    _DIM = "\033[2m"

    _SEVERITY_COLORS = {
        Severity.HIGH: "\033[91m",  # bright red
        Severity.MEDIUM: "\033[93m",  # bright yellow
        Severity.LOW: "\033[96m",  # bright cyan
    }

    lines = []
    for f in findings:
        if color:
            sev_color = _SEVERITY_COLORS[f.severity]
            badge = f"{sev_color}{_BOLD}[{f.severity.value}]{_RESET}"
            addr = f"{_BOLD}{f.address}{_RESET}"
            attr = f"{_DIM}{f.attribute}{_RESET}"
        else:
            badge = f"[{f.severity.value}]"
            addr = f.address
            attr = f.attribute

        lines.append(f"{badge} {addr}")
        lines.append(f"  attribute : {attr}")
        lines.append(f"  value     : {f.value}")
        lines.append(f"  reason    : {f.reason}")
        lines.append("")

    # Summary line at the end
    high = sum(1 for f in findings if f.severity == Severity.HIGH)
    medium = sum(1 for f in findings if f.severity == Severity.MEDIUM)
    low = sum(1 for f in findings if f.severity == Severity.LOW)

    if color:
        summary = (
            f"{_BOLD}Summary:{_RESET} "
            f"\033[91m{high} HIGH\033[0m  "
            f"\033[93m{medium} MEDIUM\033[0m  "
            f"\033[96m{low} LOW\033[0m"
        )
    else:
        summary = f"Summary: {high} HIGH  {medium} MEDIUM  {low} LOW"

    lines.append(summary)
    return "\n".join(lines)
