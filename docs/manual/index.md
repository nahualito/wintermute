# Operator Manual

Welcome to the Wintermute Operator Manual. This guide provides the tactical information required to deploy and operate the framework in various engagement scenarios.

## Initial Deployment

Before initiating an operation, ensure your environment is correctly provisioned. Wintermute requires a Linux-based host with Python 3.11+.

### Prerequisites

- **Python**: 3.11 or newer.
- **Project Manager**: `hatch`.
- **API Access**: Valid credentials for at least one supported AI provider (OpenAI, Bedrock, Groq, etc.).

### Installation

```bash
# Clone the repository
git clone https://github.com/nahualito/wintermute.git
cd wintermute

# Enter the virtual environment
hatch shell
```

## Core Workflows

### 1. Initializing the Console

The `WintermuteConsole` is your primary interface. It orchestrates the connection between the neural routing engine and the target hardware.

### 2. Neural Routing Configuration

Configure your AI providers in the environment or via the console settings. Wintermute uses `litellm` for seamless provider switching.

### 3. Hardware Interfacing

Connect to target hardware using the supported cartridges. For example, to interface with a TPM 2.0 module:
`wintermute hardware tpm20 --analyze`

## Advanced Operations

Refer to the specific sub-sections for detailed guides on:

- **Test Plan Execution**: Running structured automated audits.
- **Custom Cartridge Development**: Extending Wintermute's reach to new hardware.
- **RAG Operations**: Feeding technical documentation into the neural engine.
