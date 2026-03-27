"""
tf-state-explorer — parser.py

Reads a terraform.tfstate file (local path or HTTP(S) URL) and returns a
normalized, provider-agnostic representation of its resources, data sources,
and outputs.

Supported state format versions: 4 (Terraform >= 0.13).
Version 3 is partially handled with a warning.

Public API
----------
    parser = StateParser()
    state  = parser.parse("terraform.tfstate")
    state  = parser.parse("https://my-bucket.s3.amazonaws.com/prod.tfstate")
"""

from __future__ import annotations

import json
import re
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class TFResource:
    """
    A single normalized resource or data source extracted from the state.

    One TFResource corresponds to one *instance* of a Terraform resource block.
    When a resource uses `count` or `for_each`, each instance becomes its own
    TFResource with a suffixed name (e.g. "server[0]", "server[1]").
    """

    type: str                       # Resource type,  e.g. "aws_instance"
    name: str                       # Resource name,  e.g. "web"
    provider: str                   # Short provider, e.g. "aws"
    mode: str                       # "managed" for resources, "data" for data sources
    module: Optional[str]           # Module path, e.g. "module.vpc", or None for root
    attributes: dict                # Flat key/value map of all resource attributes
    dependencies: list[str]         # Addresses of resources this one depends on
    raw: dict = field(repr=False)   # Original JSON block, kept for edge-case access

    @property
    def address(self) -> str:
        """
        Full Terraform-style address including the module prefix.

        Examples:
            aws_instance.web
            module.vpc.aws_instance.web
            data.aws_ami.ubuntu
            module.app.data.aws_ami.ubuntu
        """
        prefix = f"{self.module}." if self.module else ""
        if self.mode == "data":
            return f"{prefix}data.{self.type}.{self.name}"
        return f"{prefix}{self.type}.{self.name}"

    @property
    def short_address(self) -> str:
        """
        Address without the module prefix — useful for display purposes.

        Examples:
            aws_instance.web          (same as address when at root)
            aws_instance.web          (strips "module.vpc." prefix)
            data.aws_ami.ubuntu
        """
        if self.mode == "data":
            return f"data.{self.type}.{self.name}"
        return f"{self.type}.{self.name}"


@dataclass
class TFOutput:
    """A single output value declared in the Terraform state."""

    name: str        # Output name as declared in outputs.tf
    value: object    # Actual value (any JSON-serializable type); None if sensitive
    sensitive: bool  # True when Terraform marks the output as sensitive
    type: str        # Terraform type string, e.g. "string", "list", "map"


@dataclass
class ParsedState:
    """
    Complete normalized representation of a terraform.tfstate file.

    Attributes:
        terraform_version:  Version of Terraform that last wrote this state.
        serial:             Monotonically increasing state revision number.
        lineage:            Unique ID assigned when the state was first created.
        resources:          Managed resources (mode == "managed").
        data_sources:       Data sources (mode == "data").
        outputs:            Declared output values.
        warnings:           Non-fatal anomalies encountered during parsing
                            (unknown format version, empty resource blocks, ...).
    """

    terraform_version: str
    serial: int
    lineage: str
    resources: list[TFResource]
    data_sources: list[TFResource]
    outputs: list[TFOutput]
    warnings: list[str]

    @property
    def all_resources(self) -> list[TFResource]:
        """Returns managed resources and data sources combined."""
        return self.resources + self.data_sources

    def by_type(self, resource_type: str) -> list[TFResource]:
        """Returns all managed resources matching the given type."""
        return [r for r in self.resources if r.type == resource_type]

    def by_provider(self, provider: str) -> list[TFResource]:
        """Returns all managed resources belonging to the given provider."""
        return [r for r in self.resources if r.provider == provider]

    def by_module(self, module: str) -> list[TFResource]:
        """Returns all resources (managed + data) inside the given module."""
        return [r for r in self.all_resources if r.module == module]


# ---------------------------------------------------------------------------
# Provider extraction
# ---------------------------------------------------------------------------

# Matches the modern registry format introduced in Terraform 0.13:
#   provider["registry.terraform.io/hashicorp/aws"]  ->  "aws"
#   provider["registry.terraform.io/datadog/datadog"]  ->  "datadog"
_PROVIDER_RE = re.compile(
    r'provider\["registry\.terraform\.io/[^/]+/([^"]+)"\]'
)

# Matches the legacy format used in Terraform < 0.13:
#   provider.aws  ->  "aws"
_LEGACY_PROVIDER_RE = re.compile(r'provider\.(\w+)')


def _extract_provider(raw_provider: str) -> str:
    """
    Extracts the short provider name from the raw provider string.

    Handles both the modern registry format (Terraform >= 0.13) and the
    legacy dot-notation format (Terraform < 0.13).  Falls back to a truncated
    version of the raw string when neither pattern matches.

    Args:
        raw_provider: Raw provider string as found in the state JSON.

    Returns:
        Short provider name (e.g. "aws", "google", "azurerm").
    """
    m = _PROVIDER_RE.search(raw_provider)
    if m:
        return m.group(1)

    m = _LEGACY_PROVIDER_RE.search(raw_provider)
    if m:
        return m.group(1)

    # Unknown format — return a truncated version to avoid losing the value
    return raw_provider[:40]


# ---------------------------------------------------------------------------
# Resource parsing
# ---------------------------------------------------------------------------

def _parse_resource(raw: dict, warnings: list[str]) -> list[TFResource]:
    """
    Converts a raw resource block from the state JSON into a list of TFResource.

    A single resource block can contain multiple instances when `count` or
    `for_each` is used.  Each instance is flattened into its own TFResource
    with an index suffix appended to the name (e.g. "server[0]", "server[1]").

    Args:
        raw:      The raw resource dict as parsed from the state JSON.
        warnings: Mutable list; non-fatal issues are appended here.

    Returns:
        A list of TFResource instances (empty if the block has no instances).
    """
    results = []

    res_type = raw.get("type", "unknown_type")
    res_name = raw.get("name", "unknown_name")
    provider = _extract_provider(raw.get("provider", ""))
    mode = raw.get("mode", "managed")
    module = raw.get("module")  # None when the resource lives at the root level

    instances = raw.get("instances", [])
    if not instances:
        # A resource block with no instances is technically valid (e.g. count = 0)
        # but there is nothing to parse — record a warning and skip.
        warnings.append(f"Resource with no instances skipped: {res_type}.{res_name}")
        return results

    for idx, instance in enumerate(instances):
        attributes = instance.get("attributes") or {}
        dependencies = instance.get("dependencies") or []

        # Append an index suffix only when there are multiple instances so that
        # single-instance resources keep a clean name (e.g. "web" not "web[0]").
        name = res_name if len(instances) == 1 else f"{res_name}[{idx}]"

        results.append(TFResource(
            type=res_type,
            name=name,
            provider=provider,
            mode=mode,
            module=module,
            attributes=attributes,
            dependencies=dependencies,
            raw=raw,
        ))

    return results


# ---------------------------------------------------------------------------
# Output parsing
# ---------------------------------------------------------------------------

def _parse_outputs(raw_outputs: dict) -> list[TFOutput]:
    """
    Converts the raw outputs dict from the state JSON into a list of TFOutput.

    Args:
        raw_outputs: The "outputs" object from the state JSON (may be empty).

    Returns:
        A list of TFOutput instances, one per declared output.
    """
    outputs = []
    for name, data in raw_outputs.items():
        outputs.append(TFOutput(
            name=name,
            value=data.get("value"),
            sensitive=data.get("sensitive", False),
            type=str(data.get("type", "unknown")),
        ))
    return outputs


# ---------------------------------------------------------------------------
# Source loading
# ---------------------------------------------------------------------------

from urllib.parse import urlparse

def _load_source(source: str) -> dict:
    parsed_url = urlparse(source)
    
    if parsed_url.scheme in ("http", "https"):
        # Scheme explicitly validated — safe to open
        with urllib.request.urlopen(source, timeout=15) as resp:  # nosec B310
            raw = resp.read().decode("utf-8")
        return json.loads(raw)
    
    if parsed_url.scheme and parsed_url.scheme not in ("", "file"):
        raise ValueError(f"Unsupported URL scheme '{parsed_url.scheme}'. Only http/https are allowed.")

    # Local file path
    path = Path(source)
    if not path.exists():
        raise FileNotFoundError(f"State file not found: {source}")
    if not path.is_file():
        raise ValueError(f"Path is not a regular file: {source}")

    return json.loads(path.read_text(encoding="utf-8"))

# ---------------------------------------------------------------------------
# Version check
# ---------------------------------------------------------------------------

# Only version 4 is fully tested and supported.
# Version 3 (Terraform < 0.13) uses a different schema and may parse partially.
_SUPPORTED_VERSIONS = {4}


def _check_version(data: dict, warnings: list[str]) -> None:
    """
    Appends a warning when the state format version is not fully supported.

    Args:
        data:     Parsed state JSON.
        warnings: Mutable list; a warning is appended when version is unknown.
    """
    version = data.get("version")
    if version not in _SUPPORTED_VERSIONS:
        warnings.append(
            f"State format version '{version}' is not fully supported "
            f"(supported: {_SUPPORTED_VERSIONS}). Parsing may be incomplete."
        )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

class StateParser:
    """
    Main entry point for parsing a Terraform state file.

    Accepts a local file path or an HTTP(S) URL (e.g. a pre-signed S3 URL).
    Returns a fully normalized ParsedState object that downstream modules
    (resources, secrets, graph) can consume without touching raw JSON.

    Usage:
        parser = StateParser()
        state  = parser.parse("terraform.tfstate")
        state  = parser.parse("https://my-bucket.s3.amazonaws.com/prod.tfstate")

        # Iterate over managed resources
        for resource in state.resources:
            print(resource.address, resource.provider)

        # Filter by type or provider
        instances = state.by_type("aws_instance")
        aws_only  = state.by_provider("aws")
    """

    def parse(self, source: str) -> ParsedState:
        """
        Parses a tfstate file and returns a normalized ParsedState.

        Args:
            source: Local file path or HTTP(S) URL pointing to a .tfstate file.

        Returns:
            A ParsedState with resources, data sources, outputs, and warnings.

        Raises:
            FileNotFoundError: If the local file does not exist.
            ValueError:        If the JSON is invalid or the top-level type is
                               not a JSON object.
        """
        warnings: list[str] = []

        try:
            data = _load_source(source)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid JSON in '{source}': {exc}") from exc

        if not isinstance(data, dict):
            raise ValueError(
                f"tfstate must be a JSON object, got {type(data).__name__}"
            )

        # Emit a warning for unsupported format versions but continue parsing
        _check_version(data, warnings)

        resources: list[TFResource] = []
        data_sources: list[TFResource] = []

        for raw_resource in data.get("resources", []):
            parsed = _parse_resource(raw_resource, warnings)
            for r in parsed:
                if r.mode == "data":
                    data_sources.append(r)
                else:
                    resources.append(r)

        outputs = _parse_outputs(data.get("outputs") or {})

        return ParsedState(
            terraform_version=data.get("terraform_version", "unknown"),
            serial=data.get("serial", 0),
            lineage=data.get("lineage", ""),
            resources=resources,
            data_sources=data_sources,
            outputs=outputs,
            warnings=warnings,
        )
