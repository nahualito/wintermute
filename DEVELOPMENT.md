# Development Guide

> Contributor reference for building, extending, and understanding Wintermute internals.

---

## Table of Contents

- [Local Environment Setup](#local-environment-setup)
- [Architecture](#architecture)
- [How to Build and Mount a New Tool](#how-to-build-and-mount-a-new-tool)
- [How to Load a Custom LoRA or RAG Shard](#how-to-load-a-custom-lora-or-rag-shard)

---

## Local Environment Setup

### Prerequisites

- Python 3.11+ (3.12 and 3.13 also supported)
- [Hatch](https://hatch.pypa.io/) (build/environment manager)
- Node.js (for Prettier and CSpell in CI checks)
- Docker (optional, for Qdrant server)

### 1. Clone and Create the Environment

```bash
git clone https://github.com/nahualito/wintermute.git
cd wintermute
hatch env create
```

Hatch reads `pyproject.toml` and installs all dependencies (including `llama-index`, `qdrant-client`, `boto3`, `litellm`, `sentence-transformers`, `mcp`, `asyncssh`, `depthcharge`, etc.) into an isolated virtualenv.

### 2. Configure API Keys

Create a `.env` file in the project root. The AI subsystem reads these at initialization:

```bash
# Required for AWS Bedrock (Claude, Titan Embeddings, DeepSeek, Llama)
AWS_REGION=us-east-1
AWS_ACCESS_KEY_ID=AKIA...
AWS_SECRET_ACCESS_KEY=...
BEDROCK_MODEL_ID=bedrock/us.anthropic.claude-3-5-sonnet-20241022-v2:0

# Optional: additional LLM providers
GROQ_API_KEY=gsk_...
OPENAI_API_KEY=sk-...

# Optional: Qdrant authentication (for remote Qdrant servers)
QDRANT_API_KEY=

# Optional: RAG defaults (override per-KB via rag_config.json)
DEFAULT_RAG_PROVIDER=bedrock
DEFAULT_EMBED_PROVIDER=local_embedder
DEFAULT_EMBED_MODEL=BAAI/bge-small-en-v1.5

# Optional: Tool path root (default: /opt)
WINTERMUTE_TOOLS_ROOT=/opt
```

> AWS credentials can also come from `~/.aws/credentials` or IAM roles. The `BEDROCK_MODEL_ID` sets the default model for the `Router`.

### 3. Setting Up Local Qdrant

For development with Qdrant-backed RAG knowledge bases:

```bash
# Option A: Docker (remote server mode)
docker run -p 6333:6333 qdrant/qdrant

# Option B: Embedded (no server needed)
# Just set "db_path" in your rag_config.json — qdrant-client runs in-process.
```

### 4. Running Checks

```bash
# Full lint + type check + formatting check
hatch run check

# Auto-fix lint and formatting issues
hatch run format

# Run tests with coverage (70% minimum enforced)
hatch run -- coverage run -m pytest && hatch run -- coverage report

# Single test file
hatch run -- pytest tests/test_core.py

# Single test function
hatch run -- pytest tests/test_core.py::test_function_name
```

### 5. Build the Package

```bash
hatch build
```

### 6. Entry Points

The project registers two CLI entry points in `pyproject.toml`:

| Command          | Module                              | Description                         |
| ---------------- | ----------------------------------- | ----------------------------------- |
| `wintermute`     | `wintermute.WintermuteConsole:main` | Interactive Metasploit-style REPL   |
| `wintermute-mcp` | `wintermute.WintermuteMCP:main`     | MCP server (SSE or stdio transport) |

---

## Architecture

### High-Level Flow

```
User Input (Console or MCP Client)
        │
        ▼
┌───────────────────┐
│  WintermuteConsole │  or  WintermuteMCP (80+ tools)
│  (REPL / cmd_ai)  │
└────────┬──────────┘
         │
         ▼
┌───────────────────┐     ┌───────────────────────────────┐
│      Router       │────▶│        LLMRegistry            │
│                   │     │  ┌─────────────────────────┐   │
│  choose(req) ─────│────▶│  │ bedrock                 │   │
│                   │     │  │ openai                  │   │
│  task_tag routing │     │  │ groq                    │   │
│  (cheap → Groq)   │     │  │ local_embedder          │   │
│                   │     │  │ rag-tiny_hardware_test  │   │
│                   │     │  │ rag-red_team_manuals_v1 │   │
│                   │     │  └─────────────────────────┘   │
└───────────────────┘     └───────────────────────────────┘
         │
         ▼
┌───────────────────┐
│    LLMProvider    │ (Protocol: chat, embed, list_models, count_tokens)
│                   │
│  If RAGProvider:  │
│  1. Query index   │──▶ LlamaIndex VectorStoreIndex
│  2. Augment prompt│     (local storage_db/ or Qdrant)
│  3. Forward to    │
│     base provider │
└────────┬──────────┘
         │
         ▼
┌───────────────────┐
│   ChatResponse    │
│  ┌──────────────┐ │
│  │ content      │ │  ← Text answer
│  │ tool_calls[] │ │  ← Functions the LLM wants to invoke
│  └──────────────┘ │
└────────┬──────────┘
         │ (if tool_calls)
         ▼
┌───────────────────┐
│   ToolsRuntime    │
│                   │
│  1. Check dynamic │──▶ SurgeonBackend (MCP subprocess)
│     backends      │    MCPRuntime (stdio MCP servers)
│  2. Fallback to   │
│     local tools   │──▶ ToolRegistry (Python handlers)
│  3. Return result │
└───────────────────┘
```

### How the Agent Routes Queries

1. **User sends a message** via `cmd_ai` (console) or an MCP tool call.
2. **`Router.choose()`** selects a provider based on:
   - The current `default_provider` (set via `router.set_default()` or `ai rag use <name>`).
   - The `task_tag` on the request (e.g., `"cheap"` routes to Groq if available).
3. **If the provider is a `RAGProvider`:**
   - The last user message is sent to the LlamaIndex `query_engine`.
   - Retrieved context is injected into the prompt as a preamble.
   - The augmented request is forwarded to the `base_provider` (e.g., Bedrock).
4. **If the provider is a base LLM** (Bedrock, OpenAI, Groq):
   - The request goes directly to the cloud API via `litellm.completion()`.
   - If `tools` are attached to the request, the LLM may return `tool_calls`.
5. **If the response contains `tool_calls`:**
   - `ToolsRuntime.run_tool()` checks dynamic backends first (Surgeon, MCP servers).
   - Falls back to the local `ToolRegistry` for static Python tools.
   - Results are returned to the LLM for the next turn.

### Key Modules

| Module                                 | Purpose                                                                        |
| -------------------------------------- | ------------------------------------------------------------------------------ |
| `ai/provider.py`                       | `LLMProvider` protocol, `LLMRegistry`, `Router`, `ModelInfo`                   |
| `ai/types.py`                          | `Message`, `ChatRequest`, `ChatResponse`, `ToolSpec`, `ToolCall`               |
| `ai/use.py`                            | `simple_chat()` and `tool_calling_chat()` high-level APIs                      |
| `ai/bootstrap.py`                      | `init_router()` registers all providers; `bootstrap_rags()` discovers KBs      |
| `ai/tools_runtime.py`                  | `ToolRegistry`, `ToolsRuntime`, `ToolBackend` protocol                         |
| `ai/providers/bedrock_provider.py`     | AWS Bedrock via LiteLLM (Claude, DeepSeek, Llama)                              |
| `ai/providers/openai_provider.py`      | OpenAI via LiteLLM (GPT-4o, o1)                                                |
| `ai/providers/groq_provider.py`        | Groq via LiteLLM (Llama 3.3 70B)                                               |
| `ai/providers/huggingface_provider.py` | Local `sentence-transformers` embeddings (bge-small, MiniLM)                   |
| `ai/providers/rag_provider.py`         | `RAGProvider`, `LlamaIndexEmbeddingWrapper`, `LlamaIndexLLMWrapper`            |
| `ai/utils/ssh_exec.py`                 | `run_command_async()`, `upload_file_async()`, `download_file_async()`          |
| `core.py`                              | `Operation`, `Device`, `Service`, `User`, `Analyst`, `TestPlan`, `TestCaseRun` |
| `basemodels.py`                        | `BaseModel` serialization with `__schema__`/`__enums__` type mapping           |
| `tickets.py`                           | `Ticket` (metaclass-based), `TicketBackend` protocol, `InMemoryBackend`        |
| `backends/storage.py`                  | `StorageBackend` protocol                                                      |
| `backends/json_storage.py`             | `JsonFileBackend` (local TinyDB persistence)                                   |
| `backends/dynamodb.py`                 | `DynamoDBBackend` (AWS DynamoDB persistence)                                   |
| `backends/bugzilla.py`                 | `BugzillaBackend` (Bugzilla REST API tickets)                                  |
| `backends/depthcharge.py`              | `DepthchargePeripheralAgent` (U-Boot automation)                               |
| `backends/docx_reports.py`             | `DocxTplPerVulnBackend` (DOCX report generation)                               |
| `integrations/mcp_runtime.py`          | `MCPRuntime` (stdio MCP client lifecycle)                                      |
| `integrations/surgeon/backend.py`      | `SurgeonController`, `SurgeonBackend`                                          |
| `integrations/surgeon/server.py`       | Surgeon FastMCP server (firmware hooks, fuzzing, symbols)                      |
| `WintermuteConsole.py`                 | REPL console with context stack, builder pattern, cartridge loader             |
| `WintermuteMCP.py`                     | MCP server exposing 80+ tools via `ObjectRegistry`                             |
| `cartridges/tpm20.py`                  | TPM 2.0 command builder, transport, and random/readpublic operations           |

### Protocol-Based Backend Pattern

All pluggable subsystems follow the same pattern:

```python
# 1. Define a protocol
class StorageBackend(Protocol):
    def save(self, operation_id: str, data: dict[str, Any]) -> bool: ...
    def load(self, operation_id: str) -> dict[str, Any] | None: ...
    def list_all(self) -> list[str]: ...
    def delete(self, operation_id: str) -> bool: ...

# 2. Implement it
class JsonFileBackend:
    def __init__(self, base_path: str = ".wintermute_data") -> None: ...
    def save(self, operation_id: str, data: dict[str, Any]) -> bool: ...
    # ...

# 3. Register at runtime
Operation.register_backend("local", JsonFileBackend("./data"), make_default=True)

# 4. Switch backends without changing application code
Operation.use_backend("cloud")
```

This pattern is used for `StorageBackend`, `TicketBackend`, `ReportBackend`, and `ToolBackend`.

---

## How to Build and Mount a New Tool

Tools are Python functions that the LLM can invoke via function calling. There are two ways to add one: as a **local static tool** or as an **MCP tool**.

### Option A: Local Static Tool

#### Step 1: Write the Handler

Create your tool handler function. It must accept a `JSONObject` (dict) and return a `JSONObject`:

```python
# wintermute/ai/utils/my_scanner.py
from wintermute.ai.json_types import JSONObject


def scan_ports(args: JSONObject) -> JSONObject:
    """Scan a target host for open ports."""
    host = str(args.get("host", ""))
    port_range = str(args.get("range", "1-1024"))
    # ... your scanning logic ...
    return {
        "host": host,
        "open_ports": [22, 80, 443],
        "scan_time_ms": 1200,
    }
```

#### Step 2: Define the JSON Schema

The LLM needs to know the function signature. Define an `input_schema` using JSON Schema:

```python
SCAN_PORTS_SCHEMA: JSONObject = {
    "type": "object",
    "properties": {
        "host": {
            "type": "string",
            "description": "Target hostname or IP address",
        },
        "range": {
            "type": "string",
            "description": "Port range to scan (e.g., '1-1024')",
            "default": "1-1024",
        },
    },
    "required": ["host"],
}
```

#### Step 3: Register with the ToolRegistry

```python
from wintermute.ai.tools_runtime import tools, Tool

tools.register(
    Tool(
        name="scan_ports",
        description="Scan a target host for open TCP ports in a given range.",
        input_schema=SCAN_PORTS_SCHEMA,
        output_schema={"type": "object"},
        handler=scan_ports,
    )
)
```

Once registered, the tool appears in `tools.get_definitions()` (OpenAI function-calling format) and is automatically available to `ToolsRuntime.run_tool()`.

#### Step 4: Expose to the LLM

When building a `ChatRequest` with tools, convert your registered tools:

```python
from wintermute.ai.tools_runtime import spec_from_tool

# Get all tools as ToolSpec objects for the ChatRequest
tool_specs = [spec_from_tool(t) for t in tools._tools.values()]
```

Or use `tools.get_definitions()` directly with providers that accept OpenAI-format tool definitions.

#### Step 5: Add Path Mapping (Optional)

If your tool wraps an external binary, create a `tools.json` that maps tool names to filesystem paths:

```json
[
  {
    "name": "scan_ports",
    "directory": "nmap/bin",
    "executable": "nmap"
  }
]
```

Load it with:

```python
tools.load_tool_configs("path/to/tools.json")
```

The resolved path (e.g., `/opt/nmap/bin/nmap`) is appended to the tool's description, so the LLM knows where the binary lives. The root is controlled by the `WINTERMUTE_TOOLS_ROOT` environment variable (default: `/opt`).

### Option B: MCP Tool (via Surgeon or Custom Server)

For tools that need process isolation, run in a different language, or require their own dependencies:

#### Step 1: Write a FastMCP Server

```python
# my_tools/server.py
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("my-security-tools")


@mcp.tool()
async def decompile_binary(firmware_path: str) -> str:
    """Decompile a firmware binary and return function signatures."""
    # ... your logic ...
    return "Found 42 functions"


if __name__ == "__main__":
    mcp.run(transport="stdio")
```

#### Step 2: Connect via MCPRuntime

```python
from wintermute.integrations.mcp_runtime import MCPRuntime

runtime = MCPRuntime(
    command="python",
    args=["my_tools/server.py"],
)
await runtime.initialize()
# All tools from the server are now registered in the global ToolRegistry
```

#### Step 3: Or Use the Surgeon Pattern

The Surgeon subsystem provides a managed subprocess with automatic lifecycle:

```python
from wintermute.integrations.surgeon.backend import SurgeonBackend

backend = SurgeonBackend(surgeon_root="/path/to/surgeon")
await backend.start()

# Register as a dynamic backend in ToolsRuntime
tools_runtime = ToolsRuntime()
tools_runtime.register_backend(backend)

# Now ToolsRuntime.run_tool() checks Surgeon tools first
result = await tools_runtime.run_tool("decompile_binary", {"firmware_path": "fw.bin"})
```

---

## How to Load a Custom LoRA or RAG Shard

### Loading a New RAG Knowledge Base

#### Step 1: Prepare Your Documents

Create a directory under `knowledge_bases/` (or `external_repos/`):

```
knowledge_bases/
└── my_exploit_db/
    ├── rag_config.json
    ├── docs/
    │   ├── exploit_manual.pdf
    │   ├── hardware_specs.md
    │   └── protocol_reference.txt
    └── storage_db/          ← Will be created after indexing
```

#### Step 2: Create rag_config.json

**For local file-based storage** (zero external dependencies):

```json
{
  "rag_id": "my_exploit_db",
  "description": "Custom exploit database for embedded systems.",
  "base_provider_id": "bedrock",
  "embed_provider_id": "local_embedder",
  "embedding_model": "BAAI/bge-small-en-v1.5",
  "vector_store_type": "local",
  "document_types": ["pdf", "markdown", "text"],
  "created_at": "2026-03-01T00:00:00Z"
}
```

**For Qdrant** (scalable vector search):

```json
{
  "rag_id": "my_exploit_db",
  "description": "Custom exploit database for embedded systems.",
  "base_provider_id": "bedrock",
  "embedding_model": "BAAI/bge-small-en-v1.5",
  "vector_store_type": "qdrant",
  "qdrant_url": "http://localhost:6333",
  "qdrant_collection_name": "my_exploits",
  "document_types": ["pdf", "markdown"],
  "created_at": "2026-03-01T00:00:00Z"
}
```

#### Config Field Reference

| Field                    | Default                                                    | Description                                              |
| ------------------------ | ---------------------------------------------------------- | -------------------------------------------------------- |
| `rag_id`                 | Folder name                                                | Unique identifier for the knowledge base                 |
| `description`            | `""`                                                       | Human-readable description shown in `ai rag list`        |
| `base_provider_id`       | `$DEFAULT_RAG_PROVIDER` or `"bedrock"`                     | LLM used for generation after retrieval                  |
| `embed_provider_id`      | `$DEFAULT_EMBED_PROVIDER` or `"bedrock"`                   | Provider used for creating embeddings                    |
| `embedding_model`        | `$DEFAULT_EMBED_MODEL` or `"amazon.titan-embed-text-v2:0"` | Specific embedding model ID                              |
| `vector_store_type`      | `"local"`                                                  | `"local"` (file-based LlamaIndex) or `"qdrant"`          |
| `qdrant_url`             | `""`                                                       | Remote Qdrant server URL (takes priority over `db_path`) |
| `db_path`                | `""`                                                       | Local on-disk Qdrant database path                       |
| `qdrant_collection_name` | Folder name                                                | Qdrant collection name                                   |
| `document_types`         | `[]`                                                       | Metadata labels for document types                       |
| `created_at`             | `""`                                                       | ISO 8601 timestamp for tracking index freshness          |

#### Step 3: Index Your Documents

For **local file-based** storage, build the LlamaIndex storage context:

```python
from llama_index.core import VectorStoreIndex, SimpleDirectoryReader

# Load documents
documents = SimpleDirectoryReader("knowledge_bases/my_exploit_db/docs").load_data()

# Build index with local embeddings
from wintermute.ai.providers.huggingface_provider import HuggingFaceProvider
from wintermute.ai.providers.rag_provider import LlamaIndexEmbeddingWrapper

embed_provider = HuggingFaceProvider(name="local_embedder")
embed_model = LlamaIndexEmbeddingWrapper(
    provider=embed_provider,
    model_name="BAAI/bge-small-en-v1.5",
)

index = VectorStoreIndex.from_documents(documents, embed_model=embed_model)

# Persist to storage_db/
index.storage_context.persist(persist_dir="knowledge_bases/my_exploit_db/storage_db")
```

For **Qdrant**, upsert vectors directly:

```python
from qdrant_client import QdrantClient
from qdrant_client.models import VectorParams, Distance, PointStruct
from sentence_transformers import SentenceTransformer

# Connect
client = QdrantClient(url="http://localhost:6333")

# Create collection (384 dimensions for bge-small)
client.create_collection(
    collection_name="my_exploits",
    vectors_config=VectorParams(size=384, distance=Distance.COSINE),
)

# Embed and upsert
model = SentenceTransformer("BAAI/bge-small-en-v1.5")
texts = ["Document chunk 1...", "Document chunk 2..."]
vectors = model.encode(texts).tolist()

points = [
    PointStruct(id=i, vector=vec, payload={"text": text})
    for i, (vec, text) in enumerate(zip(vectors, texts))
]
client.upsert(collection_name="my_exploits", points=points)
```

#### Step 4: Bootstrap Discovers It Automatically

When `init_router()` or `bootstrap_rags()` runs, your new KB is picked up:

```python
from wintermute.ai.bootstrap import init_router

router = init_router()
# Your KB is now registered as "rag-my_exploit_db"
```

Verify in the console:

```
onoSendai > ai rag list
  rag-my_exploit_db        Custom exploit database for embedded systems.
  rag-tiny_hardware_test   Hardware technical reference...

onoSendai > ai rag use my_exploit_db
onoSendai > ai What exploits target UART boot loaders?
```

### Loading a Custom Embedding Model

To use a different HuggingFace embedding model (e.g., a fine-tuned or LoRA-adapted model):

#### Step 1: Set the Model in rag_config.json

```json
{
  "embed_provider_id": "local_embedder",
  "embedding_model": "your-org/your-fine-tuned-bge-model"
}
```

The `HuggingFaceProvider` uses `sentence-transformers` under the hood. Any model compatible with `SentenceTransformer("model-name")` works — including LoRA-merged checkpoints pushed to HuggingFace Hub.

#### Step 2: For Local Model Files

If your model isn't on HuggingFace Hub, point to a local directory:

```json
{
  "embedding_model": "/path/to/my-fine-tuned-model"
}
```

`SentenceTransformer` accepts local paths. The model is lazy-loaded on first use and cached in `HuggingFaceProvider._models`.

#### Step 3: Adjust Vector Dimensions

If your custom model produces embeddings with different dimensions than the default 384 (bge-small), ensure your Qdrant collection matches:

```python
client.create_collection(
    collection_name="my_collection",
    vectors_config=VectorParams(
        size=768,  # Match your model's output dimensions
        distance=Distance.COSINE,
    ),
)
```

### Switching the Base LLM for a RAG Shard

Each RAG shard can use a different base LLM for generation. Set `base_provider_id` in `rag_config.json` to any registered provider:

```json
{
  "base_provider_id": "openai"
}
```

Or override the default via environment variable:

```bash
DEFAULT_RAG_PROVIDER=groq
```

The retrieval (embedding + vector search) and generation (LLM response) steps are fully decoupled — you can embed with `local_embedder` and generate with `bedrock`, or any other combination.

---

## Code Conventions

- **Strict mypy** is enforced (`strict = true`). All functions need type annotations.
- Use modern Python 3.11+ syntax: `list[str]` not `List[str]`, `str | None` not `Optional[str]`.
- Ruff handles linting and formatting with isort-compatible import sorting (`extend-select = ["I"]`).
- No placeholders or `pass` blocks in implementations.
- New features require unit tests in `tests/` (70% coverage minimum).
- Star imports expose only modules, not functions.
- Dataclasses use `__schema__` and `__enums__` class attributes for nested type mapping in `BaseModel`.
