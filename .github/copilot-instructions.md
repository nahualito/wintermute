# Wintermute AI Coding Agent Instructions

Essential context for AI agents working in the Wintermute codebase. Read `CLAUDE.md` at the project root for build commands and conventions.

## Architecture Overview

Wintermute is a modular AI agent framework for hardware security auditing. Python 3.11+ required. Build system: **Hatch** with **Hatchling** backend.

### Core Modules

| Module                      | Purpose                                                                                           |
| --------------------------- | ------------------------------------------------------------------------------------------------- |
| `wintermute/core.py`        | `Operation`, `Device`, `Service`, `User`, `Analyst`, `TestPlan`, `TestCaseRun` — the domain model |
| `wintermute/basemodels.py`  | `BaseModel` — serialization with `__schema__`/`__enums__` type mapping, datetime/IP coercion      |
| `wintermute/findings.py`    | `Vulnerability`, `Risk`, `ReproductionStep`                                                       |
| `wintermute/peripherals.py` | `UART`, `JTAG`, `Wifi`, `Ethernet`, `Bluetooth`, `USB`, `PCIe`, `TPMPeripheral`                   |
| `wintermute/tickets.py`     | `Ticket` (metaclass-based facade), `TicketBackend` protocol, `InMemoryBackend`                    |
| `wintermute/reports.py`     | `Report` (metaclass-based facade), `ReportBackend` protocol, `ReportSpec`                         |

### AI Subsystem (`wintermute/ai/`)

| Module                                 | Purpose                                                                                   |
| -------------------------------------- | ----------------------------------------------------------------------------------------- |
| `ai/provider.py`                       | `LLMProvider` protocol, `LLMRegistry` (global `llms` singleton), `Router`, `ModelInfo`    |
| `ai/types.py`                          | `Message`, `ChatRequest`, `ChatResponse`, `ToolSpec`, `ToolCall`                          |
| `ai/use.py`                            | `simple_chat()` and `tool_calling_chat()` high-level APIs                                 |
| `ai/bootstrap.py`                      | `init_router()` registers providers; `bootstrap_rags()` discovers RAG knowledge bases     |
| `ai/tools_runtime.py`                  | `Tool`, `ToolRegistry` (global `tools` singleton), `ToolsRuntime`, `ToolBackend` protocol |
| `ai/providers/bedrock_provider.py`     | AWS Bedrock via LiteLLM                                                                   |
| `ai/providers/openai_provider.py`      | OpenAI via LiteLLM                                                                        |
| `ai/providers/groq_provider.py`        | Groq via LiteLLM                                                                          |
| `ai/providers/huggingface_provider.py` | Local sentence-transformers embeddings (`local_embedder`)                                 |
| `ai/providers/rag_provider.py`         | `RAGProvider`, `LlamaIndexEmbeddingWrapper`, `LlamaIndexLLMWrapper`                       |
| `ai/utils/ssh_exec.py`                 | `run_command_async()`, `upload_file_async()`, `download_file_async()` via asyncssh        |

### Backends (`wintermute/backends/`)

| Module                     | Purpose                                          |
| -------------------------- | ------------------------------------------------ |
| `backends/storage.py`      | `StorageBackend` protocol                        |
| `backends/json_storage.py` | `JsonFileBackend` — local TinyDB                 |
| `backends/dynamodb.py`     | `DynamoDBBackend` — AWS DynamoDB                 |
| `backends/bugzilla.py`     | `BugzillaBackend` — Bugzilla REST API tickets    |
| `backends/depthcharge.py`  | `DepthchargePeripheralAgent` — U-Boot automation |
| `backends/docx_reports.py` | `DocxTplPerVulnBackend` — DOCX report generation |

### Integrations (`wintermute/integrations/`)

| Module                            | Purpose                                                                       |
| --------------------------------- | ----------------------------------------------------------------------------- |
| `integrations/mcp_runtime.py`     | `MCPRuntime` — stdio MCP client lifecycle, bridges tools into global registry |
| `integrations/surgeon/backend.py` | `SurgeonController`, `SurgeonBackend` — MCP subprocess management             |
| `integrations/surgeon/server.py`  | FastMCP server: firmware hooks, symbol listing, fuzzing, build                |

### Entry Points

| Command          | Module                              | Description                       |
| ---------------- | ----------------------------------- | --------------------------------- |
| `wintermute`     | `wintermute.WintermuteConsole:main` | Interactive Metasploit-style REPL |
| `wintermute-mcp` | `wintermute.WintermuteMCP:main`     | MCP server (SSE or stdio)         |

## Key Design Patterns

- **Protocol-based backends**: `StorageBackend`, `TicketBackend`, `ReportBackend`, `ToolBackend` — register and swap at runtime via `register_backend()`/`use_backend()`.
- **Metaclass facades**: `Ticket` and `Report` use metaclasses (`TicketMeta`, `ReportMeta`) to inject class methods that delegate to the active backend.
- **Provider registry**: `LLMRegistry` (global `llms`) stores all LLM providers. `Router.choose()` selects provider per request.
- **RAG auto-discovery**: `bootstrap_rags()` scans `knowledge_bases/` for `rag_config.json` files and registers `RAGProvider` instances.
- **Star imports** expose only modules, not functions (`from wintermute import *` gives `wintermute.core`, not individual classes).
- **Serialization**: `BaseModel.to_dict()`/`from_dict()` with `__schema__` for nested type coercion and `__enums__` for enum mapping.

## Code Conventions

- **Strict mypy** (`strict = true`). All functions need type annotations.
- Modern Python 3.11+: `list[str]` not `List[str]`, `str | None` not `Optional[str]`.
- **Ruff** for linting and formatting with isort-compatible import sorting.
- No placeholders or `pass` blocks.
- New features require unit tests in `tests/` (70% coverage minimum).

## Developer Workflows

- **Build**: `hatch env create` (install), `hatch build` (package).
- **Check**: `hatch run check` (ruff, mypy, prettier, cspell).
- **Format**: `hatch run format` (ruff fix + prettier).
- **Test**: `hatch run -- coverage run -m pytest && hatch run -- coverage report`.
- **Docs**: MkDocs with mkdocstrings, mkdocs-jupyter. API reference auto-generated by `gen_ref_pages.py`.
