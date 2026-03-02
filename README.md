[![ci](https://github.com/nahualito/wintermute/actions/workflows/ci.yml/badge.svg)](https://github.com/nahualito/wintermute/actions/workflows/ci.yml)
[![Python 3.11](https://img.shields.io/badge/python-3.11-blue.svg)](https://www.python.org/downloads/release/python-3110/)
[![Python 3.12](https://img.shields.io/badge/python-3.12-blue.svg)](https://www.python.org/downloads/release/python-3120/)
[![Python 3.13](https://img.shields.io/badge/python-3.13-blue.svg)](https://www.python.org/downloads/release/python-3130/)

![](docs/assets/images/wintermute_log.svg)

# Wintermute

> _"The sky above the port was the color of television, tuned to a dead channel."_

**Wintermute** is a modular, provider-agnostic AI agent framework for hardware security auditing and penetration testing automation. It bridges structured security operations with LLM-driven intelligence — routing queries to tools, knowledge bases, and cloud services through a single, unified runtime.

Define an operation. Attach devices, cloud accounts, and analysts. Load an AI agent backed by Bedrock, OpenAI, or Groq. Point it at your hardware datasheets via RAG. Let it catalog U-Boot commands, flag dangerous configurations, generate DOCX reports, and file tickets — all from a Metasploit-style console or an MCP server that any AI client can drive.

---

## &#x26A1; Key Features

&#x1F9E0; **Multi-Provider AI Agent**
Route queries to AWS Bedrock (Claude, DeepSeek, Llama), OpenAI (GPT-4o), or Groq (Llama 3.3 70B) through the `Router` class. Switch providers at runtime with a single call to `router.set_default()`. Cheap tasks auto-route to Groq.

&#x1F4DA; **Dynamic RAG Loading**
Drop a `rag_config.json` and a vector index into `knowledge_bases/` and Wintermute auto-discovers it at boot. Choose between **local file-based** indices (LlamaIndex + `BAAI/bge-small-en-v1.5`) or **Qdrant** vector databases (remote server or embedded on-disk). The AI queries your hardware datasheets, exploit manuals, and protocol specs before answering.

&#x1F527; **Unified Tool Registry**
Register Python functions, load path-mapped binaries, or connect MCP servers — they all appear as callable tools to the LLM. The `ToolsRuntime` orchestrates execution across local handlers and dynamic backends like the **Surgeon** MCP server for firmware analysis and fault injection.

&#x1F50C; **Hardware-First Peripherals**
First-class support for UART, JTAG, SPI, I2C, SWD, TPM 2.0, Bluetooth, Zigbee, USB, PCIe, Wi-Fi, and Ethernet interfaces. The `DepthchargePeripheralAgent` automates U-Boot command cataloging, danger assessment, and memory dumping — attaching `Vulnerability` objects directly to your operation.

&#x1F3AB; **Protocol-Based Backends**
Storage (JSON / DynamoDB), tickets (Bugzilla / In-Memory), and reports (DOCX templates) all use Python protocols. Register and swap backends at runtime without changing application code.

&#x1F4E1; **MCP Server**
`wintermute-mcp` exposes 80+ tools over SSE or stdio, letting any MCP-compatible AI client (Claude Desktop, Cursor, custom agents) create operations, manage devices, run scans, and generate reports.

&#x1F52E; **Cartridge System**
Load and unload offensive modules (TPM 2.0 fuzzing, IoT scanners) dynamically from the console. Cartridges are Python plugins in `wintermute/cartridges/`.

---

## &#x1F680; Quick Start

### 1. Install

```bash
pip install wintermute
```

Or from source:

```bash
git clone https://github.com/nahualito/wintermute.git
cd wintermute
hatch env create
```

### 2. Launch the Console

```bash
wintermute
```

You'll be greeted by the Wintermute REPL:

```
 __        ___       _                            _
 \ \      / (_)_ __ | |_ ___ _ __ _ __ ___  _   _| |_ ___
  \ \ /\ / /| | '_ \| __/ _ \ '__| '_ ` _ \| | | | __/ _ \
   \ V  V / | | | | | ||  __/ |  | | | | | | |_| | ||  __/
    \_/\_/  |_|_| |_|\__\___|_|  |_| |_| |_|\__,_|\__\___|

onoSendai > _
```

### 3. Create an Operation

```
onoSendai > operation create Neuromancer
onoSendai [Neuromancer] > set start_date 03/01/2026
onoSendai [Neuromancer] > set end_date 03/31/2026
```

### 4. Add Assets

```
onoSendai [Neuromancer] > add device gibson 192.168.1.55
onoSendai [Neuromancer] > add analyst Case console_cowboy case@wintermute.ai
onoSendai [Neuromancer] > add user admin "Admin User" admin@corp.local
onoSendai [Neuromancer] > add cloudaccount prod-aws aws
```

### 5. Configure Storage & Save

```
onoSendai [Neuromancer] > backend
onoSendai [Neuromancer/backend] > setup json ./data
onoSendai [Neuromancer/backend] > back
onoSendai [Neuromancer] > save
```

### 6. Load the AI Agent

```
onoSendai [Neuromancer] > ai on
```

> **Tip:** Set `AWS_REGION`, `BEDROCK_MODEL_ID`, `GROQ_API_KEY`, or `OPENAI_API_KEY` in your `.env` before launching. The router initializes all available providers automatically.

### 7. Query with RAG

```
onoSendai [Neuromancer] > ai rag list
  rag-tiny_hardware_test  Hardware technical reference...
  rag-red_team_manuals_v1 Embedded systems and red team exploit manuals.

onoSendai [Neuromancer] > ai rag use tiny_hardware_test
onoSendai [Neuromancer] > ai What voltage does the VCC_CORE pin use on the Wintermute Quantum Processor?
```

The agent retrieves context from your indexed datasheets, augments the prompt, and answers using the base LLM.

### 8. Generate a Report

```
onoSendai [Neuromancer] > ai Generate a vulnerability report for this operation in DOCX format.
```

---

## &#x1F9F1; Architecture Overview

```
                        ┌───────────────────────────────────┐
                        │         WintermuteConsole         │
                        │      (Metasploit-style REPL)      │
                        └──────────────┬────────────────────┘
                                       │
                        ┌──────────────▼────────────────────┐
                        │           Operation               │
                        │  ┌─────────┬──────────┬────────┐  │
                        │  │ Devices │  Users   │ Cloud  │  │
                        │  │ Services│ Analysts │  Accts │  │
                        │  │ Periph. │ TestPlans│ Vulns  │  │
                        │  └─────────┴──────────┴────────┘  │
                        └──────────────┬────────────────────┘
                                       │
              ┌────────────────────────┼────────────────────────┐
              │                        │                        │
   ┌──────────▼──────────┐  ┌─────────▼──────────┐  ┌─────────▼──────────┐
   │    AI Subsystem      │  │   Storage Backend   │  │   Ticket Backend   │
   │                      │  │                     │  │                    │
   │  Router ──► Provider │  │  JsonFileBackend    │  │  InMemoryBackend   │
   │  ┌────────────────┐  │  │  DynamoDBBackend    │  │  BugzillaBackend   │
   │  │ Bedrock        │  │  └─────────────────────┘  └────────────────────┘
   │  │ OpenAI         │  │
   │  │ Groq           │  │  ┌─────────────────────┐  ┌────────────────────┐
   │  │ HuggingFace    │  │  │   Report Backend    │  │    Cartridges      │
   │  │ RAGProvider(s) │  │  │                     │  │                    │
   │  └────────────────┘  │  │  DocxTplPerVuln     │  │  tpm20             │
   │                      │  └─────────────────────┘  └────────────────────┘
   │  ToolsRuntime        │
   │  ┌────────────────┐  │
   │  │ Local Tools    │  │
   │  │ MCP / Surgeon  │  │
   │  │ SSH Exec       │  │
   │  └────────────────┘  │
   └──────────────────────┘
```

---

## &#x1F916; MCP Server

Run Wintermute as a headless MCP server for integration with AI clients:

```bash
# SSE transport (default)
wintermute-mcp --host 127.0.0.1 --port 31337

# stdio transport (for Claude Desktop, Cursor, etc.)
wintermute-mcp --transport stdio
```

The server exposes all operation, device, vulnerability, test plan, AI, and reporting tools over the Model Context Protocol — enabling any compatible client to orchestrate full security assessments programmatically.

---

## &#x1F4DA; RAG Knowledge Bases

Wintermute auto-discovers knowledge bases from `knowledge_bases/` and `external_repos/` directories. Each KB needs a `rag_config.json`:

**Local file-based index:**

```json
{
  "rag_id": "hardware_specs",
  "description": "Processor pinouts, voltage levels, and JTAG headers.",
  "base_provider_id": "bedrock",
  "embed_provider_id": "local_embedder",
  "embedding_model": "BAAI/bge-small-en-v1.5",
  "vector_store_type": "local",
  "document_types": ["pdf", "text"]
}
```

**Qdrant vector database:**

```json
{
  "rag_id": "exploit_manuals",
  "description": "Red team exploit manuals and embedded systems references.",
  "base_provider_id": "bedrock",
  "embedding_model": "BAAI/bge-small-en-v1.5",
  "vector_store_type": "qdrant",
  "qdrant_url": "http://localhost:6333",
  "qdrant_collection_name": "exploit_kb"
}
```

> **Tip:** Use `BAAI/bge-small-en-v1.5` with the `local_embedder` provider for fully offline, zero-cost embeddings. Switch to `amazon.titan-embed-text-v2:0` on Bedrock for production-scale indexing.

---

## &#x1F50C; Supported Peripherals

| Peripheral | Class                | Protocol                    |
| ---------- | -------------------- | --------------------------- |
| UART       | `UART`               | Serial (RS-232/TTL)         |
| JTAG       | `JTAG`               | IEEE 1149.1                 |
| SPI        | `Peripheral(SPI)`    | Serial Peripheral Interface |
| I2C        | `Peripheral(I2C)`    | Inter-Integrated Circuit    |
| SWD        | `Peripheral(SWD)`    | Serial Wire Debug           |
| TPM 2.0    | `TPMPeripheral`      | TCG TPM 2.0                 |
| Wi-Fi      | `Wifi`               | 802.11                      |
| Bluetooth  | `Bluetooth`          | BLE / Classic               |
| Zigbee     | `Peripheral(Zigbee)` | IEEE 802.15.4               |
| USB        | `USB`                | USB 2.0 / 3.x               |
| PCIe       | `PCIe`               | PCI Express                 |
| Ethernet   | `Ethernet`           | 802.3                       |

---

## &#x1F4D6; Examples

The `examples/` directory contains Jupyter notebooks covering the full workflow:

| Notebook                             | Topic                                             |
| ------------------------------------ | ------------------------------------------------- |
| `01-Basic-Examples.ipynb`            | Core domain: Operations, Devices, Tickets         |
| `02-Operations-and-Storage.ipynb`    | Storage backends and persistence                  |
| `03-Hardware-Security-Testing.ipynb` | Hardware peripherals and Depthcharge              |
| `04-AI-Enrichment-and-Tools.ipynb`   | LLM tool calling and AI workflows                 |
| `05-RAG-Knowledge-Bases.ipynb`       | RAG setup, local indices, and console integration |
| `06-Qdrant-RAG-Integration.ipynb`    | Qdrant vector database configuration              |

---

## &#x1F468;&#x200D;&#x1F4BB; Development

We enforce strict type checking (mypy), linting (ruff), and 70% minimum test coverage.

```bash
hatch run check          # Lint + type check
hatch run format         # Auto-fix formatting
hatch run -- pytest      # Run tests
```

See [DEVELOPMENT.md](DEVELOPMENT.md) for the full contributor guide, architecture deep-dive, and instructions for building custom tools and RAG shards.

---

## &#x1F4DC; License

MIT License. See [LICENSE](LICENSE) for details.
