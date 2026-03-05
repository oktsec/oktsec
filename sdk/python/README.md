# oktsec Python SDK

Python client for the [oktsec](https://github.com/oktsec/oktsec) security proxy — identity verification, policy enforcement, and content scanning for AI agent communication.

## Install

```bash
pip install oktsec
```

## Quick start

```python
from oktsec import Client

with Client("http://localhost:8080", "my-agent") as c:
    resp = c.send_message("recipient", "hello from Python")
    print(resp.status, resp.message_id)
```

## With Ed25519 signing

```python
from oktsec import Client, load_keypair

kp = load_keypair("./keys", "my-agent")
with Client("http://localhost:8080", "my-agent", keypair=kp) as c:
    resp = c.send_message("recipient", "signed message")
    print(resp.verified_sender)  # True
```

## Async support

```python
import asyncio
from oktsec import AsyncClient

async def main():
    async with AsyncClient("http://localhost:8080", "my-agent") as c:
        resp = await c.send_message("recipient", "async hello")
        print(resp.status)

asyncio.run(main())
```

## Error handling

```python
from oktsec import Client, PolicyError

with Client("http://localhost:8080", "my-agent") as c:
    try:
        resp = c.send_message("target", "suspicious content")
    except PolicyError as e:
        print(f"Rejected: {e.response.policy_decision}")
        print(f"HTTP {e.status_code}")
        for rule in e.response.rules_triggered:
            print(f"  - {rule.rule_id}: {rule.name} ({rule.severity})")
```

## Generate keypairs

```python
from oktsec import generate_keypair

kp = generate_keypair("new-agent")
kp.save("./keys")
```

## API

### `Client(base_url, agent_name, keypair=None, timeout=30.0)`

- `send_message(to, content, metadata=None)` → `MessageResponse`
- `health()` → `HealthResponse`
- `get_quarantine(quarantine_id)` → `dict`

### `AsyncClient(base_url, agent_name, keypair=None, timeout=30.0)`

Same methods, all `async`.

### `load_keypair(directory, name)` → `Keypair`

Loads Ed25519 keys from PEM files. Compatible with `oktsec keygen` output.

### `generate_keypair(name)` → `Keypair`

Generates a new Ed25519 keypair.

## License

Apache 2.0 — same as oktsec.
