#!/usr/bin/env bash
# tf-state-explorer — tui.sh
#
# Interactive TUI for exploring a Terraform state file.
# Uses fzf for navigation and Python modules for data extraction.
#
# Usage:
#   ./tui.sh <path-to-tfstate>
#   ./tui.sh terraform.tfstate
#   ./tui.sh https://my-bucket.s3.amazonaws.com/prod.tfstate
#
# Requirements:
#   - fzf  (https://github.com/junegunn/fzf)
#   - python3 with parser.py, resources.py, secrets.py, graph.py in the same directory
#
# Key bindings in the TUI:
#   Enter       — show resource details
#   Ctrl-S      — switch to secrets scan view
#   Ctrl-G      — switch to graph / dependencies view
#   Ctrl-R      — switch to resources view (default)
#   Ctrl-O      — show outputs
#   Ctrl-Q      — quit
#   /           — filter resources (fzf built-in)

set -euo pipefail

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON="${PYTHON:-python3}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
RESET='\033[0m'

die() {
    echo -e "${RED}Error:${RESET} $*" >&2
    exit 1
}

info() {
    echo -e "${CYAN}→${RESET} $*"
}

check_dependency() {
    local cmd="$1"
    local install_hint="$2"
    if ! command -v "$cmd" &>/dev/null; then
        die "'$cmd' is required but not installed.\n  Install with: $install_hint"
    fi
}

check_python_module() {
    local module="$1"
    if ! "$PYTHON" -c "import $module" &>/dev/null; then
        die "Python module '$module' not found.\n  Make sure $module.py is in: $SCRIPT_DIR"
    fi
}

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

usage() {
    cat <<EOF
Usage: $(basename "$0") <tfstate-path-or-url>

Interactively explore a Terraform state file.

Arguments:
  tfstate-path-or-url   Path to a local .tfstate file or an HTTP(S) URL
                        (e.g. a pre-signed S3 URL)

Key bindings:
  Enter       Show resource attributes
  Ctrl-S      Secrets scan view
  Ctrl-G      Dependency graph view
  Ctrl-R      Resources view (default)
  Ctrl-O      Outputs view
  Ctrl-Q      Quit

Examples:
  $(basename "$0") terraform.tfstate
  $(basename "$0") /path/to/prod.tfstate
  $(basename "$0") https://bucket.s3.amazonaws.com/terraform.tfstate
EOF
}

if [[ $# -eq 0 ]]; then
    usage
    exit 0
fi

if [[ "$1" == "-h" || "$1" == "--help" ]]; then
    usage
    exit 0
fi

STATE_SOURCE="$1"

# ---------------------------------------------------------------------------
# Pre-flight checks
# ---------------------------------------------------------------------------

check_dependency fzf "brew install fzf  OR  apt install fzf  OR  https://github.com/junegunn/fzf"
check_dependency python3 "https://www.python.org/downloads/"

# Verify Python modules are importable from the script directory
cd "$SCRIPT_DIR"
for module in parser resources secrets graph; do
    check_python_module "$module"
done

# ---------------------------------------------------------------------------
# Python helpers — inline scripts called by the TUI
# ---------------------------------------------------------------------------

# Print summary header
py_summary() {
    "$PYTHON" - "$STATE_SOURCE" <<'PYEOF'
import sys
from parser import StateParser
from resources import summary, format_summary

state = StateParser().parse(sys.argv[1])
print(format_summary(summary(state), color=True))
PYEOF
}

# List all resources for fzf input (one per line)
py_list_resources() {
    "$PYTHON" - "$STATE_SOURCE" <<'PYEOF'
import sys
from parser import StateParser
from resources import format_resource

state = StateParser().parse(sys.argv[1])
for r in sorted(state.resources, key=lambda x: x.address):
    print(format_resource(r, color=True))
PYEOF
}

# Show attributes for a given resource address
py_show_resource() {
    local address="$1"
    "$PYTHON" - "$STATE_SOURCE" "$address" <<'PYEOF'
import sys
import json
from parser import StateParser

state = StateParser().parse(sys.argv[1])
address = sys.argv[2]

# Strip ANSI codes from address (fzf may include them)
import re
clean_address = re.sub(r'\x1b\[[0-9;]*m', '', address).strip()

# Find the resource
resource = next(
    (r for r in state.all_resources if r.address == clean_address),
    None
)

if resource is None:
    print(f"Resource not found: {clean_address}")
    sys.exit(0)

bold  = "\033[1m"
cyan  = "\033[36m"
dim   = "\033[2m"
reset = "\033[0m"
yellow = "\033[33m"

print(f"{bold}Address:{reset}   {cyan}{resource.address}{reset}")
print(f"{bold}Type:{reset}      {resource.type}")
print(f"{bold}Provider:{reset}  {resource.provider}")
print(f"{bold}Mode:{reset}      {resource.mode}")
if resource.module:
    print(f"{bold}Module:{reset}    {resource.module}")
print()

print(f"{bold}Attributes:{reset}")
for k, v in sorted(resource.attributes.items()):
    if v is None or v == "" or v == [] or v == {}:
        continue
    v_str = json.dumps(v) if not isinstance(v, str) else v
    if len(v_str) > 100:
        v_str = v_str[:100] + "..."
    print(f"  {dim}{k}{reset} = {v_str}")

if resource.dependencies:
    print()
    print(f"{bold}Dependencies:{reset}")
    for dep in sorted(resource.dependencies):
        print(f"  {yellow}→{reset} {dep}")
PYEOF
}

# Show secrets scan results
py_show_secrets() {
    local severity="${1:-LOW}"
    "$PYTHON" - "$STATE_SOURCE" "$severity" <<'PYEOF'
import sys
from parser import StateParser
from secrets import scan, format_findings, Severity

state = StateParser().parse(sys.argv[1])
min_sev = Severity[sys.argv[2]]
findings = scan(state, min_severity=min_sev)
print(format_findings(findings, color=True))
PYEOF
}

# Show outputs
py_show_outputs() {
    "$PYTHON" - "$STATE_SOURCE" <<'PYEOF'
import sys
from parser import StateParser

state = StateParser().parse(sys.argv[1])

bold   = "\033[1m"
red    = "\033[91m"
green  = "\033[32m"
dim    = "\033[2m"
reset  = "\033[0m"
yellow = "\033[33m"

if not state.outputs:
    print(f"{dim}No outputs declared in this state.{reset}")
    sys.exit(0)

print(f"{bold}Outputs ({len(state.outputs)}):{reset}\n")
for o in sorted(state.outputs, key=lambda x: x.name):
    sensitive_badge = f" {red}[sensitive]{reset}" if o.sensitive else ""
    print(f"  {bold}{o.name}{reset}{sensitive_badge}")
    if o.sensitive:
        print(f"    {dim}value: [redacted by Terraform]{reset}")
    else:
        value_str = str(o.value) if o.value is not None else "null"
        if len(value_str) > 120:
            value_str = value_str[:120] + "..."
        print(f"    {dim}value:{reset} {value_str}")
    print()
PYEOF
}

# Show dependency graph stats + adjacency
py_show_graph() {
    local address="${1:-}"
    "$PYTHON" - "$STATE_SOURCE" "$address" <<'PYEOF'
import sys
import re
from parser import StateParser
from graph import build, orphans, roots, cycles, depth

state = StateParser().parse(sys.argv[1])
address = sys.argv[2] if len(sys.argv) > 2 else ""

# Strip ANSI codes
clean_address = re.sub(r'\x1b\[[0-9;]*m', '', address).strip()

g = build(state)

bold   = "\033[1m"
cyan   = "\033[36m"
yellow = "\033[33m"
red    = "\033[91m"
green  = "\033[32m"
dim    = "\033[2m"
reset  = "\033[0m"

if clean_address and clean_address in g.nodes:
    # Show details for a specific resource
    print(f"{bold}Resource:{reset} {cyan}{clean_address}{reset}")
    print(f"{bold}Depth:{reset}    {depth(g, clean_address)}")
    print()

    deps = sorted(g.dependencies_of(clean_address))
    if deps:
        print(f"{bold}Depends on ({len(deps)}):{reset}")
        for d in deps:
            print(f"  {yellow}→{reset} {d}")
    else:
        print(f"{dim}No dependencies (foundation resource){reset}")

    print()
    dependents = sorted(g.dependents_of(clean_address))
    if dependents:
        print(f"{bold}Depended on by ({len(dependents)}):{reset}")
        for d in dependents:
            print(f"  {green}←{reset} {d}")
    else:
        print(f"{dim}Nothing depends on this resource{reset}")
else:
    # Show global graph stats
    print(f"{bold}Graph stats:{reset}")
    print(f"  Nodes : {g.node_count}")
    print(f"  Edges : {g.edge_count}")
    print()

    cycle_list = cycles(g)
    if cycle_list:
        print(f"  {red}{bold}⚠ Cycles detected: {len(cycle_list)}{reset}")
        for c in cycle_list[:3]:
            print(f"    {' → '.join(c)}")
    else:
        print(f"  {green}✓ No cycles detected{reset}")

    print()
    orphan_list = orphans(g)
    print(f"{bold}Orphan resources (no dependencies): {len(orphan_list)}{reset}")
    for addr in orphan_list[:10]:
        print(f"  {dim}{addr}{reset}")
    if len(orphan_list) > 10:
        print(f"  {dim}... and {len(orphan_list) - 10} more{reset}")

    print()
    root_list = roots(g)
    print(f"{bold}Root resources (nothing depends on them): {len(root_list)}{reset}")
    for addr in root_list[:10]:
        print(f"  {dim}{addr}{reset}")
    if len(root_list) > 10:
        print(f"  {dim}... and {len(root_list) - 10} more{reset}")
PYEOF
}

# ---------------------------------------------------------------------------
# TUI views
# ---------------------------------------------------------------------------

# Main resources view — fzf list with preview
view_resources() {
    local header
    header="$(py_summary 2>/dev/null)"

    py_list_resources 2>/dev/null \
        | fzf \
            --ansi \
            --header="${header}" \
            --header-lines=0 \
            --prompt="Resources > " \
            --preview="$(declare -f py_show_resource); py_show_resource {}" \
            --preview-window="right:60%:wrap" \
            --bind="ctrl-s:execute($(declare -f py_show_secrets); py_show_secrets LOW | less -R)+abort" \
            --bind="ctrl-g:execute($(declare -f py_show_graph); py_show_graph '$STATE_SOURCE' {} | less -R)+abort" \
            --bind="ctrl-o:execute($(declare -f py_show_outputs); py_show_outputs | less -R)+abort" \
            --bind="ctrl-q:abort" \
            --bind="enter:execute($(declare -f py_show_resource); py_show_resource {} | less -R)" \
            --info=inline \
            --no-sort \
        || true
}

# Secrets view — full-screen formatted output
view_secrets() {
    local severity="${1:-MEDIUM}"
    clear
    echo -e "${BOLD}${CYAN}=== Secrets Scan ===${RESET}"
    echo -e "${DIM}State: $STATE_SOURCE${RESET}"
    echo -e "${DIM}Minimum severity: $severity${RESET}"
    echo ""
    py_show_secrets "$severity"
    echo ""
    echo -e "${DIM}Press any key to return...${RESET}"
    read -r -n 1
}

# Graph view — full-screen stats
view_graph() {
    clear
    echo -e "${BOLD}${CYAN}=== Dependency Graph ===${RESET}"
    echo -e "${DIM}State: $STATE_SOURCE${RESET}"
    echo ""
    py_show_graph ""
    echo ""
    echo -e "${DIM}Press any key to return...${RESET}"
    read -r -n 1
}

# Outputs view
view_outputs() {
    clear
    echo -e "${BOLD}${CYAN}=== Outputs ===${RESET}"
    echo -e "${DIM}State: $STATE_SOURCE${RESET}"
    echo ""
    py_show_outputs
    echo ""
    echo -e "${DIM}Press any key to return...${RESET}"
    read -r -n 1
}

# ---------------------------------------------------------------------------
# Main menu
# ---------------------------------------------------------------------------

main_menu() {
    while true; do
        clear
        echo -e "${BOLD}${CYAN}tf-state-explorer${RESET}"
        echo -e "${DIM}State: $STATE_SOURCE${RESET}"
        echo ""

        # Print summary
        py_summary 2>/dev/null || echo -e "${RED}Failed to parse state file${RESET}"
        echo ""

        echo -e "  ${BOLD}[r]${RESET} Browse resources"
        echo -e "  ${BOLD}[s]${RESET} Secrets scan"
        echo -e "  ${BOLD}[g]${RESET} Dependency graph"
        echo -e "  ${BOLD}[o]${RESET} Outputs"
        echo -e "  ${BOLD}[q]${RESET} Quit"
        echo ""
        echo -n "Choice: "
        read -r -n 1 choice
        echo ""

        case "$choice" in
            r|R) view_resources ;;
            s|S) view_secrets "MEDIUM" ;;
            g|G) view_graph ;;
            o|O) view_outputs ;;
            q|Q) echo -e "\n${DIM}Bye!${RESET}"; exit 0 ;;
            *)   echo -e "${RED}Invalid choice${RESET}"; sleep 0.5 ;;
        esac
    done
}

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

# Validate the state source before launching the TUI
info "Loading state from: $STATE_SOURCE"
if ! "$PYTHON" -c "
from parser import StateParser
import sys
try:
    StateParser().parse(sys.argv[1])
    print('OK')
except Exception as e:
    print(f'ERROR: {e}', file=sys.stderr)
    sys.exit(1)
" "$STATE_SOURCE" 2>/dev/null | grep -q "OK"; then
    die "Failed to parse state file: $STATE_SOURCE"
fi

echo -e "${GREEN}✓${RESET} State loaded successfully"
sleep 0.5

main_menu
