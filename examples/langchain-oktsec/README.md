# LangChain + oktsec

Secure LangChain agent-to-agent communication with oktsec scanning.

## Architecture

```
LangChain Agent → oktsec proxy → MCP Server (tools)
                      ↓
              content scanning
              identity verification
              audit trail
```

## Setup

```bash
# Install dependencies
pip install oktsec langchain langchain-community

# Setup oktsec
oktsec setup
oktsec serve --config oktsec.yaml
```

## Run

```bash
python agent.py
```

## How it works

The agent uses the oktsec Python SDK to route all inter-agent messages through the security proxy. Every tool call and response is scanned for prompt injection, credential leaks, and other threats before delivery.

The MCP servers are wrapped via `oktsec setup`, so all MCP tool calls are automatically intercepted at the stdio level — no code changes needed in the LangChain agent itself.
