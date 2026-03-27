# tf-state-explorer

[![CI](https://github.com/hemeric-aissi/tf-state-explorer/actions/workflows/ci.yml/badge.svg)](https://github.com/hemeric-aissi/tf-state-explorer/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.12%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

A CLI tool to interactively explore Terraform state files — browse resources by type and provider, detect exposed secrets, and visualize dependencies.

`terraform.tfstate` files are verbose, deeply nested, and painful to read manually. This tool parses them into a clean, navigable structure so you can understand your infrastructure at a glance.

---

## Features

- **Browse resources** — list and filter by type, provider, or module
- **Detect secrets** — surface sensitive values exposed in outputs or attributes (IPs, ARNs, access keys...)
- **Visualize dependencies** — reconstruct the dependency graph between resources
- **Interactive TUI** — navigate with `fzf`, preview attributes live
- **Multiple output formats** — terminal display, JSON/CSV export, Markdown report
- **Remote state support** — read from a local file or a pre-signed S3 URL

---

## Project status

This project is under active development. The parser module is complete and tested. The following modules are in progress:

| Module | Status |
|---|---|
| `parser.py` | ✅ Complete |
| `resources.py` | 🚧 In progress |
| `secrets.py` | 🔜 Planned |
| `graph.py` | 🔜 Planned |
| `tui.sh` | 🔜 Planned |

---

## Requirements

- Python 3.12+
- `fzf` (for the interactive TUI)

---

## Installation

```bash
git clone https://github.com/hemeric-aissi/tf-state-explorer.git
cd tf-state-explorer
pip install -r requirements.txt
```

---

## Usage

### Parse a local state file

```python
from parser import StateParser

state = StateParser().parse("terraform.tfstate")

# List all managed resources
for resource in state.resources:
    print(resource.address, resource.provider)

# Filter by type
instances = state.by_type("aws_instance")

# Filter by provider
aws_resources = state.by_provider("aws")

# Filter by module
vpc_resources = state.by_module("module.vpc")
```

### Parse a remote state file (pre-signed S3 URL)

```python
state = StateParser().parse("https://my-bucket.s3.amazonaws.com/prod.tfstate")
```

### Inspect outputs

```python
for output in state.outputs:
    if output.sensitive:
        print(f"⚠ Sensitive output: {output.name}")
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
│   └── test_parser.py      # 44 unit tests for parser.py
├── parser.py               # State parser — core module
├── requirements.txt
├── .gitignore
└── README.md
```

---

## CI pipeline

Every pull request to `main` runs 4 mandatory checks:

| Check | Tool | Purpose |
|---|---|---|
| Secret scan | TruffleHog | Detect secrets in code and git history |
| Lint & format | Ruff | Enforce code style and formatting |
| Static security analysis | Bandit | Detect security anti-patterns in Python |
| Tests | pytest | Run the full test suite |

All actions are pinned to a specific commit SHA to prevent supply chain attacks.

---

## Running tests locally

```bash
pip install -r requirements.txt
python -m pytest tests/ -v
```

---

## Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feat/your-feature`
3. Commit your changes following [Conventional Commits](https://www.conventionalcommits.org/)
4. Open a pull request — the CI pipeline must pass before merging

---

## License

MIT
