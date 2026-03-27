"""
tf-state-explorer — resources.py

Provides functions to list, group, filter, and summarize resources extracted
from a parsed Terraform state.  Consumes ParsedState from parser.py — never
touches raw JSON directly.

Public API
----------
    from resources import group_by_provider, group_by_type, group_by_module, summary

    state = StateParser().parse("terraform.tfstate")

    by_provider = group_by_provider(state)   # {"aws": [TFResource, ...], ...}
    by_type     = group_by_type(state)        # {"aws_instance": [...], ...}
    by_module   = group_by_module(state)      # {"module.vpc": [...], None: [...]}
    info        = summary(state)              # ResourceSummary dataclass
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass

from parser import ParsedState, TFResource


# ---------------------------------------------------------------------------
# Summary dataclass
# ---------------------------------------------------------------------------


@dataclass
class ResourceSummary:
    """
    High-level counts extracted from a parsed state.

    Useful for a quick overview before diving into individual resources,
    e.g. "12 resources across 3 providers and 2 modules".

    Attributes:
        total_resources:   Number of managed resources (mode == "managed").
        total_data_sources: Number of data sources (mode == "data").
        providers:         Set of unique provider names present in the state.
        resource_types:    Set of unique resource types present in the state.
        modules:           Set of module paths (None means root level).
        counts_by_provider: Mapping of provider name -> resource count.
        counts_by_type:    Mapping of resource type -> resource count.
        counts_by_module:  Mapping of module path -> resource count.
                           None key represents root-level resources.
    """

    total_resources: int
    total_data_sources: int
    providers: set[str]
    resource_types: set[str]
    modules: set[str | None]
    counts_by_provider: dict[str, int]
    counts_by_type: dict[str, int]
    counts_by_module: dict[str | None, int]


# ---------------------------------------------------------------------------
# Grouping functions
# ---------------------------------------------------------------------------


def group_by_provider(state: ParsedState) -> dict[str, list[TFResource]]:
    """
    Groups managed resources by their provider name.

    Only managed resources (mode == "managed") are included.
    Data sources are excluded — use state.data_sources directly if needed.

    Args:
        state: A ParsedState returned by StateParser.parse().

    Returns:
        A dict mapping provider name to the list of resources for that provider.
        Keys are sorted alphabetically for consistent output.

    Example:
        {
            "aws":    [TFResource(type="aws_instance", ...), ...],
            "google": [TFResource(type="google_compute_instance", ...), ...],
        }
    """
    groups: dict[str, list[TFResource]] = defaultdict(list)
    for resource in state.resources:
        groups[resource.provider].append(resource)
    return dict(sorted(groups.items()))


def group_by_type(state: ParsedState) -> dict[str, list[TFResource]]:
    """
    Groups managed resources by their resource type.

    Only managed resources (mode == "managed") are included.

    Args:
        state: A ParsedState returned by StateParser.parse().

    Returns:
        A dict mapping resource type to the list of resources of that type.
        Keys are sorted alphabetically for consistent output.

    Example:
        {
            "aws_instance":       [TFResource(...), TFResource(...)],
            "aws_security_group": [TFResource(...)],
            "aws_s3_bucket":      [TFResource(...)],
        }
    """
    groups: dict[str, list[TFResource]] = defaultdict(list)
    for resource in state.resources:
        groups[resource.type].append(resource)
    return dict(sorted(groups.items()))


def group_by_module(state: ParsedState) -> dict[str | None, list[TFResource]]:
    """
    Groups all resources (managed + data sources) by their module path.

    Root-level resources (not inside any module) are grouped under the None key.

    Args:
        state: A ParsedState returned by StateParser.parse().

    Returns:
        A dict mapping module path (or None for root) to a list of resources.
        String keys are sorted alphabetically; None key comes last.

    Example:
        {
            "module.app": [TFResource(...), ...],
            "module.vpc": [TFResource(...), ...],
            None:         [TFResource(...), ...],   # root-level resources
        }
    """
    groups: dict[str | None, list[TFResource]] = defaultdict(list)
    for resource in state.all_resources:
        groups[resource.module].append(resource)

    # Sort: named modules alphabetically first, None (root) last
    sorted_keys = sorted(
        groups.keys(),
        key=lambda k: (k is None, k or ""),
    )
    return {k: groups[k] for k in sorted_keys}


# ---------------------------------------------------------------------------
# Filter functions
# ---------------------------------------------------------------------------


def filter_resources(
    state: ParsedState,
    *,
    provider: str | None = None,
    resource_type: str | None = None,
    module: str | None = None,
    name_contains: str | None = None,
) -> list[TFResource]:
    """
    Returns managed resources matching all of the supplied filters.

    All filters are optional and combined with AND logic — only resources
    satisfying every supplied condition are returned.

    Args:
        state:          A ParsedState returned by StateParser.parse().
        provider:       If set, keep only resources from this provider.
        resource_type:  If set, keep only resources of this type.
        module:         If set, keep only resources inside this module.
                        Pass an empty string "" to match root-level resources.
        name_contains:  If set, keep only resources whose name contains this
                        substring (case-insensitive).

    Returns:
        A filtered list of TFResource instances.

    Example:
        # All AWS EC2 instances inside module.app
        results = filter_resources(
            state,
            provider="aws",
            resource_type="aws_instance",
            module="module.app",
        )
    """
    results = state.resources

    if provider is not None:
        results = [r for r in results if r.provider == provider]

    if resource_type is not None:
        results = [r for r in results if r.type == resource_type]

    if module is not None:
        # Empty string "" is treated as root level (module == None)
        target_module = None if module == "" else module
        results = [r for r in results if r.module == target_module]

    if name_contains is not None:
        needle = name_contains.lower()
        results = [r for r in results if needle in r.name.lower()]

    return results


# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------


def summary(state: ParsedState) -> ResourceSummary:
    """
    Computes a high-level summary of the parsed state.

    Aggregates counts by provider, type, and module in a single pass over
    the resource list.

    Args:
        state: A ParsedState returned by StateParser.parse().

    Returns:
        A ResourceSummary dataclass with counts and sets of unique values.
    """
    counts_by_provider: dict[str, int] = defaultdict(int)
    counts_by_type: dict[str, int] = defaultdict(int)
    counts_by_module: dict[str | None, int] = defaultdict(int)

    providers: set[str] = set()
    resource_types: set[str] = set()
    modules: set[str | None] = set()

    for resource in state.resources:
        counts_by_provider[resource.provider] += 1
        counts_by_type[resource.type] += 1
        counts_by_module[resource.module] += 1
        providers.add(resource.provider)
        resource_types.add(resource.type)
        modules.add(resource.module)

    return ResourceSummary(
        total_resources=len(state.resources),
        total_data_sources=len(state.data_sources),
        providers=providers,
        resource_types=resource_types,
        modules=modules,
        counts_by_provider=dict(sorted(counts_by_provider.items())),
        counts_by_type=dict(sorted(counts_by_type.items())),
        counts_by_module=dict(counts_by_module),
    )


# ---------------------------------------------------------------------------
# Formatting helpers
# ---------------------------------------------------------------------------


# ANSI color codes for terminal output
_RESET = "\033[0m"
_BOLD = "\033[1m"
_DIM = "\033[2m"
_CYAN = "\033[36m"
_YELLOW = "\033[33m"
_GREEN = "\033[32m"
_MAGENTA = "\033[35m"


def format_resource(resource: TFResource, *, color: bool = True) -> str:
    """
    Formats a single TFResource as a human-readable string for terminal output.

    The format is:
        <type>.<name>  [<provider>]  (<module>)   # when inside a module
        <type>.<name>  [<provider>]               # when at root level

    Args:
        resource: The TFResource to format.
        color:    When True, applies ANSI color codes. Set to False when
                  writing to a file or piping to another command.

    Returns:
        A formatted string representing the resource.
    """
    if color:
        type_part = f"{_CYAN}{resource.type}{_RESET}"
        name_part = f"{_BOLD}{resource.name}{_RESET}"
        provider_part = f"{_DIM}[{resource.provider}]{_RESET}"
        module_part = (
            f"  {_YELLOW}({resource.module}){_RESET}" if resource.module else ""
        )
    else:
        type_part = resource.type
        name_part = resource.name
        provider_part = f"[{resource.provider}]"
        module_part = f"  ({resource.module})" if resource.module else ""

    return f"{type_part}.{name_part}  {provider_part}{module_part}"


def format_summary(s: ResourceSummary, *, color: bool = True) -> str:
    """
    Formats a ResourceSummary as a multi-line human-readable string.

    Produces a compact overview like:
        Resources:    12 managed, 3 data sources
        Providers:    aws (8), google (4)
        Types:        7 unique
        Modules:      module.app, module.vpc + root

    Args:
        s:     A ResourceSummary returned by summary().
        color: When True, applies ANSI color codes.

    Returns:
        A formatted multi-line string.
    """
    bold = _BOLD if color else ""
    reset = _RESET if color else ""
    green = _GREEN if color else ""
    magenta = _MAGENTA if color else ""
    dim = _DIM if color else ""

    # Build provider counts string: "aws (8), google (4)"
    provider_counts = ", ".join(
        f"{name} ({count})" for name, count in s.counts_by_provider.items()
    )

    # Build module list: named modules + "root" if any root resources
    module_names = [m for m in s.modules if m is not None]
    module_names.sort()
    if None in s.modules:
        module_names.append("root")
    modules_str = ", ".join(module_names) if module_names else "root only"

    lines = [
        f"{bold}Resources:{reset}    "
        f"{green}{s.total_resources} managed{reset}, "
        f"{dim}{s.total_data_sources} data sources{reset}",
        f"{bold}Providers:{reset}    {magenta}{provider_counts}{reset}",
        f"{bold}Types:{reset}        {len(s.resource_types)} unique",
        f"{bold}Modules:{reset}      {modules_str}",
    ]

    return "\n".join(lines)
