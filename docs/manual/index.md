# Operator Manual

This manual covers the Wintermute console, the Python API for each subsystem, and the configuration formats for RAG knowledge bases and tool registration.

---

## Console Reference

### Starting the Console

```bash
wintermute
```

The console uses a **context stack** that changes the available commands based on where you are:

- **Root** (`onoSendai >`) — Create operations, manage backends.
- **Operation** (`onoSendai [OpName] >`) — Add/edit/delete entities, configure AI, save/load.
- **Builder** (`onoSendai [OpName/device:host] >`) — Set properties on the entity being built.
- **Backend** (`onoSendai [OpName/backend] >`) — Configure storage, AI, and ticket backends.

### Core Commands

| Command                               | Context   | Description                                     |
| ------------------------------------- | --------- | ----------------------------------------------- |
| `operation create <name>`             | Root      | Create a new operation and enter it             |
| `save`                                | Operation | Persist operation to the active storage backend |
| `load <name>`                         | Operation | Load an operation from storage                  |
| `add device <hostname> <ip>`          | Operation | Add a device to the operation                   |
| `add analyst <name> <userid> <email>` | Operation | Add an analyst                                  |
| `add user <uid> <name> <email>`       | Operation | Add a user                                      |
| `add cloudaccount <name> <type>`      | Operation | Add a cloud account (`aws` or `generic`)        |
| `add service <device> <port> <app>`   | Operation | Add a service to a device                       |
| `edit <path>`                         | Operation | Enter builder mode for an existing entity       |
| `delete <path>`                       | Operation | Remove an entity (with confirmation)            |
| `set <key> <value>`                   | Builder   | Set a property on the current entity            |
| `show`                                | Builder   | Display current entity properties               |
| `back`                                | Any       | Pop one level from the context/builder stack    |
| `status`                              | Operation | Render a Rich tree view of the entire operation |
| `vars <path>`                         | Operation | Inspect properties at a dot-separated path      |

### AI Commands

| Command             | Description                                                      |
| ------------------- | ---------------------------------------------------------------- |
| `ai on`             | Initialize the AI router (registers all available providers)     |
| `ai <prompt>`       | Send a prompt to the current AI provider                         |
| `ai rag list`       | List all discovered RAG knowledge bases                          |
| `ai rag use <name>` | Switch the router to a RAG provider (e.g., `tiny_hardware_test`) |
| `ai rag off`        | Switch back to the base LLM provider (no RAG augmentation)       |

### Backend Commands

Enter with `backend` from an operation context:

| Command                  | Description                                            |
| ------------------------ | ------------------------------------------------------ |
| `setup json <path>`      | Register a `JsonFileBackend` at the given directory    |
| `setup dynamodb <table>` | Register a `DynamoDBBackend` with the given table name |
| `list`                   | List saved operations in the active backend            |
| `available`              | Show all available backend types                       |

### Cartridge Commands

| Command                | Description                             |
| ---------------------- | --------------------------------------- |
| `use <cartridge>`      | Load a cartridge module (e.g., `tpm20`) |
| `set <option> <value>` | Configure a loaded cartridge option     |
| `run`                  | Execute the loaded cartridge            |
| `use none`             | Unload the current cartridge            |

---

## Python API

### Operation

The central aggregate that composes all domain objects.

```python
from wintermute.core import Operation
```

#### Constructor

```python
Operation(
    operation_name: str = "",
    operation_id: str = "",       # Auto-generated UUID if empty
    start_date: str = "",         # Format: MM/DD/YYYY
    end_date: str = "",
    ticket: str | None = None,
)
```

#### Methods

| Method                | Parameters                                                      | Returns             | Description                              |
| --------------------- | --------------------------------------------------------------- | ------------------- | ---------------------------------------- |
| `addDevice`           | `hostname`, `ipaddr`, `macaddr`, `operatingsystem`, `fqdn`, ... | `bool`              | Add a device to the operation            |
| `addAnalyst`          | `name`, `userid`, `email`                                       | `bool`              | Add an analyst                           |
| `addUser`             | `uid`, `name`, `email`, `teams`, ...                            | `bool`              | Add a user                               |
| `addCloudAccount`     | `name`, `cloud_type`, `description`, `account_id`, ...          | `bool`              | Add a cloud account                      |
| `addTestPlan`         | `plan: TestPlan \| dict`                                        | `bool`              | Add a test plan (accepts dict or object) |
| `getDeviceByHostname` | `hostname: str`                                                 | `Device \| None`    | Look up a device                         |
| `generateTestRuns`    | `replace: bool = False`                                         | `list[TestCaseRun]` | Resolve bindings and create test runs    |
| `statusReport`        | `start: datetime`, `end: datetime`                              | `dict`              | Aggregate test run stats                 |
| `save`                | —                                                               | `bool`              | Persist to the active storage backend    |
| `load`                | —                                                               | `bool`              | Load from the active storage backend     |

#### Backend Registration

```python
from wintermute.backends.json_storage import JsonFileBackend
from wintermute.backends.dynamodb import DynamoDBBackend

# Local development
Operation.register_backend("local", JsonFileBackend("./data"), make_default=True)

# Cloud persistence
Operation.register_backend("cloud", DynamoDBBackend(table_name="OpsTable"))

# Switch at runtime
Operation.use_backend("cloud")
```

> **Note:** `register_backend` and `use_backend` are class-level methods. All `Operation` instances share the active backend.

---

### Device

```python
from wintermute.core import Device
```

| Field             | Type                         | Description                 |
| ----------------- | ---------------------------- | --------------------------- |
| `hostname`        | `str`                        | Device hostname             |
| `ipaddr`          | `IPv4Address \| IPv6Address` | IP address                  |
| `macaddr`         | `str`                        | MAC address                 |
| `operatingsystem` | `str`                        | OS name                     |
| `fqdn`            | `str`                        | Fully qualified domain name |
| `architecture`    | `Architecture \| None`       | CPU architecture enum       |
| `processor`       | `Processor \| None`          | Processor type enum         |
| `services`        | `list[Service]`              | Network services            |
| `peripherals`     | `list[Peripheral]`           | Hardware interfaces         |
| `vulnerabilities` | `list[Vulnerability]`        | Attached findings           |

---

### Vulnerability

```python
from wintermute.findings import Vulnerability, Risk, ReproductionStep
```

#### Constructor

| Parameter            | Type                             | Default | Description                                    |
| -------------------- | -------------------------------- | ------- | ---------------------------------------------- |
| `title`              | `str`                            | `""`    | Vulnerability title                            |
| `description`        | `str`                            | `""`    | Detailed description                           |
| `threat`             | `str`                            | `""`    | Threat classification                          |
| `cvss`               | `int`                            | `0`     | CVSS score                                     |
| `risk`               | `Risk \| dict`                   | `{}`    | Risk assessment (likelihood, impact, severity) |
| `verified`           | `bool`                           | `False` | Whether the vulnerability was confirmed        |
| `reproduction_steps` | `list[ReproductionStep] \| None` | `None`  | Steps to reproduce                             |
| `mitigation`         | `bool`                           | `True`  | Whether mitigation exists                      |
| `mitigation_desc`    | `str`                            | `""`    | Mitigation description                         |
| `fix`                | `bool`                           | `True`  | Whether a fix exists                           |
| `fix_desc`           | `str`                            | `""`    | Fix description                                |

#### Example

```python
vuln = Vulnerability(
    title="U-Boot Environment Variable Injection",
    description="Bootloader allows arbitrary env modification via UART.",
    cvss=9,
    risk=Risk(likelihood="High", impact="Critical", severity="Critical"),
    reproduction_steps=[
        ReproductionStep(
            title="Inject init=/bin/sh",
            tool="uboot-write-env",
            action="setenv",
            arguments=["bootargs", "init=/bin/sh"],
        )
    ],
    verified=True,
)
```

---

### Ticket System

The `Ticket` class uses a metaclass to delegate operations to interchangeable backends.

```python
from wintermute.tickets import Ticket, InMemoryBackend, Status
```

#### Setup

```python
# In-memory backend (testing / air-gapped)
Ticket.register_backend("mem", InMemoryBackend(), make_default=True)

# Bugzilla backend (production)
from wintermute.backends.bugzilla import BugzillaBackend

Ticket.register_backend(
    "bugzilla",
    BugzillaBackend(
        base_url="http://bugzilla.corp.local/bugzilla",
        api_key="YOUR_API_KEY",
        default_product="FirmwareSecurity",
        default_component="Hardware",
    ),
)
```

#### Class Methods

| Method               | Parameters                                                                     | Returns  | Description                            |
| -------------------- | ------------------------------------------------------------------------------ | -------- | -------------------------------------- |
| `Ticket.create`      | `title`, `description`, `assignee?`, `requester?`, `status?`, `custom_fields?` | `str`    | Create a ticket, returns the ticket ID |
| `Ticket.read`        | `ticket_id: str`                                                               | `Ticket` | Load a ticket with data and comments   |
| `Ticket.update`      | `ticket_id: str`, `**fields`                                                   | `None`   | Update ticket fields                   |
| `Ticket.comment`     | `ticket_id: str`, `text: str`, `author: str`                                   | `None`   | Add a comment                          |
| `Ticket.use_backend` | `name: str`                                                                    | `None`   | Switch to a named backend              |

#### Implementing a Custom Backend

Any object that satisfies the `TicketBackend` protocol works:

```python
from wintermute.tickets import TicketData, Comment

class MyJiraBackend:
    def create(self, data: TicketData) -> str:
        # Call Jira API, return ticket ID
        return "JIRA-123"

    def read(self, ticket_id: str) -> tuple[TicketData, list[Comment]]:
        ...

    def update(self, ticket_id: str, fields: dict[str, Any]) -> None:
        ...

    def add_comment(self, ticket_id: str, comment: Comment) -> None:
        ...
```

---

### Report Generation

```python
from wintermute.reports import Report, ReportSpec
from wintermute.backends.docx_reports import DocxTplPerVulnBackend
```

#### Setup

```python
Report.register_backend(
    "docx",
    DocxTplPerVulnBackend(
        template_dir="templates",
        main_template="report_main.docx",
        vuln_template="report_vuln.docx",
        test_run_template="report_test_run.docx",
    ),
    make_default=True,
)
```

#### Generating a Report

```python
spec = ReportSpec(
    title="Hardware Security Audit – Q1 2026",
    author="Lead Researcher",
    summary="Critical UART and SPI flash vulnerabilities identified.",
)

# Pass any objects with .vulnerabilities attributes — the collector walks the graph
Report.save(spec, [device, peripheral, cloud_account], "audit_report.docx")
```

The `collect_vulnerabilities()` function recursively walks object graphs, extracting every `Vulnerability` instance and rendering it into the template.

---

## AI Agent Configuration

### Initializing the Router

```python
from wintermute.ai.bootstrap import init_router

router = init_router()
```

`init_router()` performs the following in order:

1. Registers `BedrockProvider` (using `AWS_REGION` env, default `us-east-1`).
2. Registers `GroqProvider` (using `GROQ_API_KEY` env).
3. Registers `OpenAIProvider` (using `OPENAI_API_KEY` env).
4. Registers `HuggingFaceProvider` as `local_embedder` (local sentence-transformers).
5. Calls `bootstrap_rags()` to auto-discover and register all RAG knowledge bases.
6. Returns a `Router` with default provider `bedrock`.

### Router API

```python
from wintermute.ai.provider import Router
```

| Method        | Parameters                      | Returns                           | Description                                     |
| ------------- | ------------------------------- | --------------------------------- | ----------------------------------------------- |
| `choose`      | `req: ChatRequest`              | `tuple[LLMProvider, ChatRequest]` | Select provider and possibly modify the request |
| `set_default` | `provider?: str`, `model?: str` | `None`                            | Change the default provider or model at runtime |

#### Routing Behavior

- The `Router` uses `default_provider` as the baseline.
- If `req.task_tag` contains `"cheap"`, it routes to the first registered Groq provider.
- Switch to RAG at runtime:

```python
# Direct LLM (no retrieval)
router.set_default(provider="bedrock")

# RAG-augmented (retrieves from indexed documents first)
router.set_default(provider="rag-tiny_hardware_test")

# Switch base model
router.set_default(model="bedrock/us.anthropic.claude-3-5-sonnet-20241022-v2:0")
```

### High-Level Chat APIs

```python
from wintermute.ai.use import simple_chat, tool_calling_chat
```

#### `simple_chat()`

| Parameter  | Type          | Default     | Description               |
| ---------- | ------------- | ----------- | ------------------------- |
| `router`   | `Router`      | —           | Router instance           |
| `prompt`   | `str`         | —           | User prompt               |
| `task_tag` | `str`         | `"generic"` | Tag for routing decisions |
| `model`    | `str \| None` | `None`      | Override model            |

**Returns:** `str` — The LLM response text.

```python
response = simple_chat(router, "What is the JTAG pinout for the STM32F4?")
```

#### `tool_calling_chat()`

| Parameter         | Type                             | Default     | Description          |
| ----------------- | -------------------------------- | ----------- | -------------------- |
| `router`          | `Router`                         | —           | Router instance      |
| `messages`        | `list[Message]`                  | —           | Conversation history |
| `tools`           | `list[ToolSpec]`                 | —           | Available tools      |
| `tool_choice`     | `"auto" \| "none" \| "required"` | `"auto"`    | Tool behavior        |
| `response_format` | `"text" \| "json"`               | `"text"`    | Output format        |
| `task_tag`        | `str`                            | `"generic"` | Tag for routing      |
| `model`           | `str \| None`                    | `None`      | Override model       |

**Returns:** `ChatResponse` — Includes `content`, `tool_calls`, token counts, and latency.

```python
from wintermute.ai.types import Message, ToolSpec

response = tool_calling_chat(
    router,
    messages=[Message(role="user", content="Scan 192.168.1.1 for open ports")],
    tools=[
        ToolSpec(
            name="scan_ports",
            description="Scan a host for open TCP ports",
            input_schema={
                "type": "object",
                "properties": {"host": {"type": "string"}},
                "required": ["host"],
            },
        )
    ],
)

if response.tool_calls:
    for tc in response.tool_calls:
        print(f"Tool: {tc.name}, Args: {tc.arguments}")
```

### Registered Providers

After `init_router()`, the global `LLMRegistry` contains:

| Provider Name    | Class                 | Models                                        |
| ---------------- | --------------------- | --------------------------------------------- |
| `bedrock`        | `BedrockProvider`     | Claude 3.5 Sonnet, DeepSeek R1, Llama 3.1 70B |
| `groq`           | `GroqProvider`        | Llama 3.3 70B, Llama 3.1 70B, Llama 3.1 8B    |
| `openai`         | `OpenAIProvider`      | GPT-4o mini, GPT-4o, o1-mini                  |
| `local_embedder` | `HuggingFaceProvider` | all-MiniLM-L6-v2, BAAI/bge-small-en-v1.5      |
| `rag-<name>`     | `RAGProvider`         | Inherits from base provider                   |

---

## RAG Knowledge Bases

### How RAG Works

1. **Discovery.** `bootstrap_rags()` scans `knowledge_bases/` and `external_repos/` for subdirectories containing either a `storage_db/` folder (local index) or a `rag_config.json` with `"vector_store_type": "qdrant"`.
2. **Index loading.** For local storage, it loads a persisted LlamaIndex `StorageContext`. For Qdrant, it creates a `QdrantClient` and wraps it in a `QdrantVectorStore`.
3. **Registration.** Each knowledge base becomes a `RAGProvider` registered as `rag-<folder_name>` in the global `LLMRegistry`.
4. **Query flow.** When the router points to a RAG provider, the last user message is sent to the LlamaIndex `query_engine`. Retrieved context is injected into the prompt as a preamble, then the augmented request is forwarded to the base LLM.

### Configuration: `rag_config.json`

Place this file in each knowledge base directory.

#### Local File-Based Index

```json
{
    "rag_id": "hardware_specs",
    "description": "Processor pinouts, voltage levels, and JTAG headers.",
    "base_provider_id": "bedrock",
    "embed_provider_id": "local_embedder",
    "embedding_model": "BAAI/bge-small-en-v1.5",
    "vector_store_type": "local",
    "document_types": ["pdf", "text"],
    "created_at": "2026-03-01T00:00:00Z"
}
```

> **Requirement:** The directory must contain a `storage_db/` folder with persisted LlamaIndex files (`docstore.json`, `default__vector_store.json`, `index_store.json`).

#### Qdrant Vector Database (Remote Server)

```json
{
    "rag_id": "red_team_manuals",
    "description": "Embedded systems and red team exploit manuals.",
    "base_provider_id": "bedrock",
    "embedding_model": "BAAI/bge-small-en-v1.5",
    "vector_store_type": "qdrant",
    "qdrant_url": "http://localhost:6333",
    "qdrant_collection_name": "exploit_kb",
    "document_types": ["pdf", "markdown"],
    "created_at": "2026-03-01T00:00:00Z"
}
```

#### Qdrant Vector Database (Local On-Disk)

```json
{
    "rag_id": "firmware_docs",
    "description": "Firmware documentation and protocol specs.",
    "base_provider_id": "bedrock",
    "embedding_model": "BAAI/bge-small-en-v1.5",
    "vector_store_type": "qdrant",
    "db_path": "./storage/firmware_docs",
    "qdrant_collection_name": "firmware_kb",
    "document_types": ["pdf", "text"]
}
```

> **No server needed.** When `db_path` is set without `qdrant_url`, qdrant-client runs an embedded database in-process.

### Config Field Reference

| Field                    | Type        | Default                                                    | Description                                              |
| ------------------------ | ----------- | ---------------------------------------------------------- | -------------------------------------------------------- |
| `rag_id`                 | `str`       | Folder name                                                | Unique identifier for the knowledge base                 |
| `description`            | `str`       | `""`                                                       | Shown in `ai rag list`                                   |
| `base_provider_id`       | `str`       | `$DEFAULT_RAG_PROVIDER` or `"bedrock"`                     | LLM for generation after retrieval                       |
| `embed_provider_id`      | `str`       | `$DEFAULT_EMBED_PROVIDER` or `"bedrock"`                   | Provider for creating embeddings                         |
| `embedding_model`        | `str`       | `$DEFAULT_EMBED_MODEL` or `"amazon.titan-embed-text-v2:0"` | Embedding model ID                                       |
| `vector_store_type`      | `str`       | `"local"`                                                  | `"local"` (file-based) or `"qdrant"`                     |
| `qdrant_url`             | `str`       | `""`                                                       | Remote Qdrant server URL (takes priority over `db_path`) |
| `db_path`                | `str`       | `""`                                                       | Local on-disk Qdrant database path                       |
| `qdrant_collection_name` | `str`       | Folder name                                                | Qdrant collection name                                   |
| `document_types`         | `list[str]` | `[]`                                                       | Metadata labels for document types                       |
| `created_at`             | `str`       | `""`                                                       | ISO 8601 timestamp for tracking index freshness          |

### Indexing Documents

#### Local File-Based

```python
from llama_index.core import VectorStoreIndex, SimpleDirectoryReader
from wintermute.ai.providers.huggingface_provider import HuggingFaceProvider
from wintermute.ai.providers.rag_provider import LlamaIndexEmbeddingWrapper

# Load documents
documents = SimpleDirectoryReader("knowledge_bases/my_kb/docs").load_data()

# Build index with local embeddings
embed_provider = HuggingFaceProvider(name="local_embedder")
embed_model = LlamaIndexEmbeddingWrapper(
    provider=embed_provider,
    model_name="BAAI/bge-small-en-v1.5",
)
index = VectorStoreIndex.from_documents(documents, embed_model=embed_model)

# Persist
index.storage_context.persist(persist_dir="knowledge_bases/my_kb/storage_db")
```

#### Qdrant

```python
from qdrant_client import QdrantClient
from qdrant_client.models import VectorParams, Distance, PointStruct
from sentence_transformers import SentenceTransformer

client = QdrantClient(url="http://localhost:6333")

# Create collection (384 dimensions for bge-small-en-v1.5)
client.create_collection(
    collection_name="exploit_kb",
    vectors_config=VectorParams(size=384, distance=Distance.COSINE),
)

# Embed and upsert
model = SentenceTransformer("BAAI/bge-small-en-v1.5")
texts = ["U-Boot allows env modification via UART...", "SPI flash lacks read protection..."]
vectors = model.encode(texts).tolist()

points = [
    PointStruct(id=i, vector=vec, payload={"text": text})
    for i, (vec, text) in enumerate(zip(vectors, texts))
]
client.upsert(collection_name="exploit_kb", points=points)
```

### Environment Variables

| Variable                 | Default                          | Description                              |
| ------------------------ | -------------------------------- | ---------------------------------------- |
| `DEFAULT_RAG_PROVIDER`   | `"bedrock"`                      | Base LLM for RAG generation              |
| `DEFAULT_EMBED_PROVIDER` | `"bedrock"`                      | Embedding provider                       |
| `DEFAULT_EMBED_MODEL`    | `"amazon.titan-embed-text-v2:0"` | Embedding model ID                       |
| `QDRANT_API_KEY`         | `""`                             | API key for authenticated Qdrant servers |

---

## Tool Registration

### Static Tool (Python Function)

```python
from wintermute.ai.tools_runtime import tools, Tool
from wintermute.ai.json_types import JSONObject


def scan_firmware(args: JSONObject) -> JSONObject:
    """Extract and analyze firmware sections."""
    path = str(args.get("path", ""))
    return {"sections": ["bootloader", "kernel", "rootfs"], "path": path}


tools.register(
    Tool(
        name="scan_firmware",
        description="Extract and analyze sections from a firmware binary.",
        input_schema={
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Path to firmware binary"}
            },
            "required": ["path"],
        },
        output_schema={"type": "object"},
        handler=scan_firmware,
    )
)
```

### Path-Mapped Tools

Map tool names to external binaries via `tools.json`:

```json
[
    { "name": "openocd", "directory": "openocd/bin", "executable": "openocd" },
    {
        "name": "flashrom",
        "directory": "flashrom/bin",
        "executable": "flashrom"
    }
]
```

```python
tools.load_tool_configs("tools.json")
# Resolved paths (e.g., /opt/openocd/bin/openocd) are appended to tool descriptions.
# Root controlled by WINTERMUTE_TOOLS_ROOT env var (default: /opt).
```

### MCP Tool (Dynamic Backend)

```python
from wintermute.integrations.mcp_runtime import MCPRuntime

runtime = MCPRuntime(command="python", args=["my_tools/server.py"])
await runtime.initialize()
# All tools from the MCP server are now in the global ToolRegistry.
```

### ToolsRuntime Orchestration

```python
from wintermute.ai.tools_runtime import ToolsRuntime

runtime = ToolsRuntime()
runtime.register_backend(surgeon_backend)  # Dynamic MCP backend

# Unified execution: checks dynamic backends first, falls back to local registry
result = await runtime.run_tool("scan_firmware", {"path": "/tmp/fw.bin"})
```

---

## MCP Server

Run Wintermute as a headless MCP server:

```bash
# SSE transport
wintermute-mcp --host 127.0.0.1 --port 31337

# stdio transport (Claude Desktop, Cursor, etc.)
wintermute-mcp --transport stdio
```

### Key Tool Categories

| Category            | Examples                                                                                        |
| ------------------- | ----------------------------------------------------------------------------------------------- |
| **Operations**      | `create_operation`, `edit_operation`, `delete_operation`, `save_operation`, `load_operation`    |
| **Devices**         | `add_device`, `edit_device`, `delete_device`, `get_device_info`                                 |
| **Services**        | `add_service_to_device`, `add_peripheral_to_device`                                             |
| **Vulnerabilities** | `addVulnerability_Device`, `addVulnerability_Service`, `add_reproduction_step_to_vulnerability` |
| **Cloud**           | `add_cloud_account`, `add_aws_account`, `add_iam_user_to_aws`, `add_iam_role_to_aws`            |
| **Test Plans**      | `add_test_plan`, `generate_test_runs`, `update_test_run_status`                                 |
| **Tickets**         | `setup_ticket_backend`, `create_ticket`, `read_ticket`, `update_ticket`                         |
| **Reports**         | `setup_report_backend`, `generate_report`                                                       |
| **AI**              | `configure_ai_router`, `set_ai_default_provider`                                                |
| **Surgeon**         | `init_mcp_surgeon`, `list_surgeon_tools`, `call_surgeon_tool`                                   |

The `ObjectRegistry` in `WintermuteMCP.py` maps human-readable string IDs (e.g., `op:acme`, `dev:gateway01`) to live Python objects, so MCP clients reference entities by stable names rather than memory addresses.

---

## Depthcharge Integration

The `DepthchargePeripheralAgent` automates U-Boot security analysis:

```python
from wintermute.backends.depthcharge import DepthchargePeripheralAgent
from wintermute.peripherals import UART

uart = UART(name="UART0", device_path="/dev/ttyUSB0")
agent = DepthchargePeripheralAgent(uart, arch="arm")

# Catalog commands, assess danger, auto-attach vulnerabilities
result = agent.catalog_commands_and_flag(addVulns=True)

# Dump memory and record as a vulnerability
agent.dump_memory_and_attach_vuln(address=0x80000000, length=0x1000)
```

The agent uses `DANGER_RULES` (regex patterns matching commands like `erase`, `mw`, `flash`) with severity weights to assess risk. Dangerous configurations automatically generate `Vulnerability` objects attached to the peripheral.

---

## Test Plans

### Defining a Test Plan

```python
from wintermute.core import TestPlan, TestCase, ObjectSelector, TargetScope
from wintermute.core import BindKind, BindCardinality, ExecutionMode

plan = TestPlan(
    code="TP-HW-001",
    name="Hardware Blackbox Audit",
    description="Baseline hardware security checks.",
    test_cases=[
        TestCase(
            code="TC-UART-001",
            name="Check UART Authentication",
            description="Verify UART console requires authentication.",
            execution_mode=ExecutionMode.per_device,
            target_scope=TargetScope(
                tags=["hardware"],
                bindings=[
                    ObjectSelector(
                        kind=BindKind.peripheral,
                        name="uart_interfaces",
                        cardinality=BindCardinality.at_least_one,
                        where={"pType": "UART"},
                    )
                ],
            ),
            steps=[],
        )
    ],
)

op.addTestPlan(plan)
runs = op.generateTestRuns()
```

### Test Run Lifecycle

| Status           | Meaning                                 |
| ---------------- | --------------------------------------- |
| `not_run`        | Generated but not yet started           |
| `in_progress`    | Currently being executed                |
| `passed`         | Test passed                             |
| `failed`         | Test failed (findings expected)         |
| `blocked`        | Cannot execute (dependency issue)       |
| `not_applicable` | Test does not apply to the bound target |
