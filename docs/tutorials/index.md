# Tutorials

Hands-on Jupyter notebooks covering Wintermute's core workflows. Each tutorial is self-contained and can be executed directly in your browser or local environment.

---

## Available Tutorials

### [01 — AI Routing & Tools](01_neural_routing.ipynb)

Initialize the `Router`, send queries through `simple_chat()`, register a custom JTAG enumeration tool, and execute it through the `ToolsRuntime`. Covers the full lifecycle from provider initialization to tool-calling execution.

### [02 — Operator Ticketing](02_bugzilla_tracking.ipynb)

Set up the `BugzillaBackend`, create hardware vulnerability tickets with custom fields, read and update ticket status, and swap to an `InMemoryBackend` for air-gapped operations — all through the unified `Ticket` class.

### [03 — Automated Reporting](03_docx_generation.ipynb)

Configure the `DocxTplPerVulnBackend` with Word templates, define `Vulnerability` and `ReproductionStep` objects for hardware findings, and generate a professional DOCX security assessment report using `Report.save()`.

---

## Running the Notebooks

```bash
# Install Jupyter (if not already available)
pip install jupyterlab

# Launch from the project root
jupyter lab examples/
```

> **Note:** Some notebooks require API keys (Bedrock, Bugzilla) configured in your environment. See the [Operator Manual](../manual/index.md) for environment variable reference.
