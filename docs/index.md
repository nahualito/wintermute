# Wintermute

> _"The sky above the port was the color of television, tuned to a dead channel."_

**Wintermute** is a modular, provider-agnostic AI agent framework for hardware security auditing and penetration testing automation. It composes structured security operations with LLM-driven intelligence — routing queries through tools, knowledge bases, and cloud services via a single unified runtime.

---

## What Wintermute Does

Wintermute manages the full lifecycle of a hardware security engagement:

1. **Model the target.** Create an `Operation`, attach `Device` objects with `Service` and `Peripheral` entries, add `User` and `CloudAccount` records, assign `Analyst` staff.
2. **Load an AI agent.** Initialize a `Router` backed by AWS Bedrock, OpenAI, or Groq. Point it at indexed hardware datasheets via the RAG engine. The agent retrieves context from your documents before answering.
3. **Execute tools.** The agent calls registered tools — local Python handlers, path-mapped binaries, or MCP servers like the Surgeon firmware analysis backend — through the `ToolsRuntime` orchestrator.
4. **Track findings.** Vulnerabilities attach directly to devices, services, peripherals, and cloud accounts. The `Ticket` system syncs findings to Bugzilla or an in-memory store. Structured `TestPlan` definitions generate `TestCaseRun` records.
5. **Generate reports.** The `DocxTplPerVulnBackend` renders professional Word documents from Jinja2 templates, composing per-vulnerability and per-test-run sections automatically.

---

## Core Subsystems

### AI Agent

| Component         | Module                         | Purpose                                                                                                                            |
| ----------------- | ------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------- |
| **Router**        | `ai/provider.py`               | Selects provider and model per request. Routes cheap tasks to Groq automatically.                                                  |
| **Providers**     | `ai/providers/`                | Bedrock (Claude, DeepSeek, Llama), OpenAI (GPT-4o), Groq (Llama 3.3), HuggingFace (local embeddings).                              |
| **RAG Engine**    | `ai/providers/rag_provider.py` | Queries LlamaIndex vector indices (local file-based or Qdrant), augments prompts with retrieved context, forwards to any base LLM. |
| **Tool Registry** | `ai/tools_runtime.py`          | `ToolRegistry` for static tools, `ToolsRuntime` for unified execution across local handlers and MCP backends.                      |
| **Bootstrap**     | `ai/bootstrap.py`              | `init_router()` registers all providers. `bootstrap_rags()` auto-discovers knowledge bases from `rag_config.json` files.           |

### Operations & Data

| Component     | Module        | Purpose                                                                             |
| ------------- | ------------- | ----------------------------------------------------------------------------------- |
| **Operation** | `core.py`     | Central aggregate: devices, users, analysts, cloud accounts, test plans, test runs. |
| **Findings**  | `findings.py` | `Vulnerability`, `Risk`, `ReproductionStep` — attach to any entity.                 |
| **Tickets**   | `tickets.py`  | Metaclass-based `Ticket` facade with pluggable backends (Bugzilla, In-Memory).      |
| **Reports**   | `reports.py`  | Metaclass-based `Report` facade. Walks object graphs to collect vulnerabilities.    |

### Backends & Integrations

| Component        | Module                        | Purpose                                                                       |
| ---------------- | ----------------------------- | ----------------------------------------------------------------------------- |
| **JSON Storage** | `backends/json_storage.py`    | `JsonFileBackend` — local TinyDB persistence.                                 |
| **DynamoDB**     | `backends/dynamodb.py`        | `DynamoDBBackend` — AWS cloud persistence.                                    |
| **DOCX Reports** | `backends/docx_reports.py`    | `DocxTplPerVulnBackend` — template-based Word report generation.              |
| **Depthcharge**  | `backends/depthcharge.py`     | `DepthchargePeripheralAgent` — U-Boot command cataloging and memory dumping.  |
| **MCP Runtime**  | `integrations/mcp_runtime.py` | Manages stdio-based MCP server lifecycle, bridges tools into global registry. |
| **Surgeon**      | `integrations/surgeon/`       | MCP server for firmware hook generation, symbol listing, fuzzing, and build.  |
| **Cartridges**   | `cartridges/`                 | Loadable offensive modules (TPM 2.0 command builder, etc.).                   |

### Interfaces

| Interface      | Entry Point      | Description                                                                      |
| -------------- | ---------------- | -------------------------------------------------------------------------------- |
| **Console**    | `wintermute`     | Metasploit-style REPL with context stack, builder pattern, and cartridge loader. |
| **MCP Server** | `wintermute-mcp` | 80+ MCP tools over SSE or stdio for AI client integration.                       |

---

## Quick Links

- **[Operator Manual](manual/index.md)** — Console commands, API reference, RAG configuration, tool registration.
- **[Tutorials](tutorials/index.md)** — Hands-on Jupyter notebooks for routing, ticketing, and reporting.
- **[API Reference](reference/SUMMARY.md)** — Auto-generated from source docstrings via mkdocstrings.
- **[Development Guide](https://github.com/nahualito/wintermute/blob/main/DEVELOPMENT.md)** — Environment setup, architecture deep-dive, contributor workflows.

---

## Installation

```bash
pip install wintermute
```

Or from source:

```bash
git clone https://github.com/nahualito/wintermute.git
cd wintermute
hatch env create
```

Launch the console:

```bash
wintermute
```

Launch the MCP server:

```bash
wintermute-mcp --transport stdio
```

---

_Wintermute — Hardware Security, Reimagined._
