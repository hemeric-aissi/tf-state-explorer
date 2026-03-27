# tf-state-explorer

[![CI](https://github.com/hemeric-aissi/tf-state-explorer/actions/workflows/ci.yml/badge.svg)](https://github.com/hemeric-aissi/tf-state-explorer/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.12%2B-blue)
![Tests](https://img.shields.io/badge/tests-206%20passing-brightgreen)
![License](https://img.shields.io/badge/license-MIT-green)

A CLI tool to interactively explore Terraform state files — browse resources, detect exposed secrets, and visualize dependencies.

`terraform.tfstate` files are verbose, deeply nested JSON files that are painful to inspect manually. This tool parses them into a clean structure and provides an interactive terminal interface to navigate resources, surface sensitive values, and understand dependency chains — without ever running `terraform`.

---

## Demo

```
tf-state-explorer
State: terraform.tfstate

Resources:    52 managed, 219 data sources
Providers:    aws (48), google (4)
Types:        12 unique
Modules:      module.app, module.vpc

  [r] Browse resources
  [s] Secrets scan
  [g] Dependency graph
  [o] Outputs
  [q] Quit
```

---

## Features

- **Browse resources** — interactive fzf list with live attribute preview, filterable by type, provider, or module
- **Detect secrets** — surface sensitive values in outputs and attributes (AWS access keys, private keys, passwords, tokens, connection strings, public IPs, ARNs...)
- **Visualize dependencies** — reconstruct the dependency graph, detect orphan resources, and export to Graphviz DOT format
- **Inspect outputs** — list all outputs with sensitive values clearly flagged
- **Remote state support** — reads from a local file or a pre-signed S3 URL
- **Provider-agnostic** — works with any Terraform provider (AWS, GCP, Azure, NSX-T, vSphere, ...)

---

## Requirements

- Python 3.12+
- `fzf` — for the interactive TUI ([install](https://github.com/junegunn/fzf#installation))

---

## Installation

```bash
git clone https://github.com/hemeric-aissi/tf-state-explorer.git
cd tf-state-explorer
pip install -r requirements.txt
chmod +x tui.sh
```

---

## Usage

### Interactive TUI

```bash
./tui.sh terraform.tfstate
./tui.sh /path/to/prod.tfstate
./tui.sh https://my-bucket.s3.amazonaws.com/prod.tfstate
```

**Key bindings in the resources view:**

| Key | Action |
|---|---|
| `Enter` | Show full resource attributes |
| `Ctrl-S` | Switch to secrets scan |
| `Ctrl-G` | Show dependency info for selected resource |
| `Ctrl-O` | Show outputs |
| `Ctrl-Q` | Quit |
| Type anything | Filter resources |

### Python API

```python
from parser import StateParser
from resources import summary, format_summary, group_by_provider
from secrets import scan, format_findings, Severity
from graph import build, orphans, to_dot

state = StateParser().parse("terraform.tfstate")

# Summary
print(format_summary(summary(state)))

# Browse resources by provider
for provider, resources in group_by_provider(state).items():
    print(f"{provider}: {len(resources)} resources")

# Scan for secrets
findings = scan(state, min_severity=Severity.MEDIUM)
print(format_findings(findings))

# Dependency graph
g = build(state)
print(f"{g.node_count} nodes, {g.edge_count} edges")
print("Orphans:", orphans(g))

# Export to Graphviz DOT
with open("graph.dot", "w") as f:
    f.write(to_dot(g))
# Render: dot -Tsvg graph.dot -o graph.svg
# Or paste at: https://dreampuf.github.io/GraphvizOnline/
```

---

## Secret detection rules

The secrets scanner uses 13 pattern-based rules across 3 severity levels:

| Severity | What is detected |
|---|---|
| `HIGH` | AWS access keys, PEM private keys, GCP service account JSON |
| `MEDIUM` | Passwords, API tokens, connection strings with credentials, GitHub/Slack tokens, sensitive outputs |
| `LOW` | Public IP addresses, AWS ARNs, internal hostnames |

Scan with minimum severity:

```python
scan(state, min_severity=Severity.HIGH)    # confirmed secrets only
scan(state, min_severity=Severity.MEDIUM)  # secrets + likely sensitive
scan(state, min_severity=Severity.LOW)     # everything (default)
```

---

## Repository structure

```
tf-state-explorer/
├── .github/
│   └── workflows/
│       └── ci.yml          # DevSecOps CI pipeline
├── tests/
│   ├── fixtures/
│   │   ├── simple_v4.tfstate       # Basic state with outputs
│   │   └── with_modules.tfstate    # State with nested modules
│   ├── test_parser.py      # 44 tests
│   ├── test_resources.py   # 55 tests
│   ├── test_secrets.py     # 52 tests
│   └── test_graph.py       # 55 tests
├── parser.py               # State parser — reads tfstate into clean dataclasses
├── resources.py            # Resource listing, filtering, grouping and formatting
├── secrets.py              # Secret detection with 13 pattern-based rules
├── graph.py                # Dependency graph construction, analysis and DOT export
├── tui.sh                  # Interactive terminal UI (requires fzf)
├── requirements.txt
├── .gitignore
└── README.md
```

---

## CI pipeline

Every pull request to `main` runs 4 mandatory checks. All actions are pinned to a specific commit SHA to prevent supply chain attacks.

| Check | Tool | Purpose |
|---|---|---|
| Secret scan | TruffleHog | Detect secrets in code and git history |
| Lint & format | Ruff | Enforce code style and formatting |
| Static security analysis | Bandit | Detect security anti-patterns in Python |
| Tests | pytest | Run the full test suite (206 tests) |

---

## Running tests

```bash
pip install -r requirements.txt
python -m pytest tests/ -v
```

---

## Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feat/your-feature`
3. Commit following [Conventional Commits](https://www.conventionalcommits.org/)
4. Open a pull request — all 4 CI checks must pass before merging

---

## License

MIT — see [LICENSE](LICENSE)
