# CrewAI + oktsec

Multi-agent CrewAI setup with oktsec scanning all inter-agent communication.

## Architecture

```
┌──────────┐     ┌──────────┐     ┌──────────┐
│ Researcher│────→│  Analyst │────→│  Writer  │
└──────────┘     └──────────┘     └──────────┘
      │                │                │
      └────────────────┼────────────────┘
                       ↓
                 oktsec proxy
              (scan + audit + policy)
```

## Setup

```bash
pip install oktsec crewai

oktsec setup
oktsec serve --config oktsec.yaml
```

## Run

```bash
python crew.py
```

## How it works

Each CrewAI agent sends its output through the oktsec proxy before the next agent receives it. This ensures:

- Prompt injection attempts between agents are caught
- Credential leaks in agent outputs are detected
- All communication is logged for audit
- Suspicious content is quarantined for human review
