# Wintermute AI Coding Agent Instructions

This guide provides essential context for AI agents working in the Wintermute codebase. It summarizes architecture, workflows, conventions, and integration points to maximize agent productivity.

## Architecture Overview
- **Core Structure:**
  - Main package: `wintermute/` with submodules: `core.py`, `basemodels.py`, `findings.py`, `peripherals.py`, `cartridges/`, `utils/`, `vendor/`.
  - Key classes: `Operation`, `Pentest`, `Analyst`, `Device`, `Service`, `Vulnerability`, `Risk`, `dbController`, `cartridge`, `User`, `Account`, `Team`.
  - Data flows: Operations and Pentests are central objects, with Analysts, Devices, Services, and Vulnerabilities linked via composition.
  - Cartridges: Plugin-like modules in `cartridges/` for hardware/offensive extensions (e.g., `tpm20`, `iot`).

## Developer Workflows
- **Console/REPL:**
  - Main entry: `./wintermuteConsole` (not `python3 -m wintermute`).
  - Console supports commands: `load`, `unload`, `run_script`, `run_pyscript`, etc.
- **Testing:**
  - Tests in `tests/` (e.g., `test_core.py`, `test_peripherals.py`).
  - Run with standard Python test runners (pytest/unittest).
- **Documentation:**
  - Sphinx-based docs in `docs/`. Build with `cd docs && make html`.
- **Docker:**
  - Can be run in Docker: `docker run -it --rm -v $(pwd):/opt/wintermute`.

## Import Patterns & Conventions
- Supports both `import wintermute` and `from wintermute import *`.
- Star imports only expose modules, not functions, to avoid polluting the namespace.
- Classes and objects are accessible via `wintermute.core`, `wintermute.database`, etc.
- Cartridges should be placed in `wintermute/cartridges/`.
- Internal classes go in `core.py`.

## Integration Points & Dependencies
- **Python 3.11+ required** (see badges in README).
- External dependencies managed via `pyproject.toml`.
- Sphinx for documentation, Docker for containerization.

## Project-Specific Patterns
- **Class diagrams and relationships** are documented in README (see mermaid diagram).
- **Command loading** in console uses `load`/`unload` for cartridges.
- **No direct function imports** via star-imports; only modules/classes.
- **Documentation and design files**: See `DEVELOPMENT.md`, `ROADMAP.md` (not included in repo, but referenced).

## Key Files & Directories
- `wintermute/core.py`: Main logic and class definitions.
- `wintermute/cartridges/`: Hardware/offensive plugins.
- `wintermute/utils/`: Utility functions (e.g., parsers, findings).
- `tests/`: Unit tests for core and cartridges.
- `docs/`: Sphinx documentation source.
- `wintermuteConsole`: Main REPL entry point.

---

**For updates, merge new conventions and patterns from README and design docs. If any section is unclear or missing, request feedback from maintainers.**
