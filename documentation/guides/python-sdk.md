# Python SDK

The Python SDK provides a client for sending messages through the Oktsec proxy.

## Installation

```bash
pip install oktsec
```

## Basic usage

```python
from oktsec import Client

client = Client("http://127.0.0.1:8080", "coordinator")

# Send a message
result = client.send_message(
    to="researcher",
    content="Analyze the latest threat report",
)

print(result.status)           # "delivered"
print(result.policy_decision)  # "allow"
print(result.rules_triggered)  # []
print(result.verified_sender)  # False (unsigned)
```

## With Ed25519 signing

```python
from oktsec import Client, load_keypair

keypair = load_keypair("./keys", "coordinator")
client = Client("http://127.0.0.1:8080", "coordinator", keypair=keypair)

# Messages are automatically signed
result = client.send_message(
    to="researcher",
    content="Analyze the latest threat report",
)
print(result.verified_sender)  # True
```

## Async support

```python
from oktsec import AsyncClient

client = AsyncClient("http://127.0.0.1:8080", "coordinator")

result = await client.send_message(
    to="researcher",
    content="Analyze the latest threat report",
)
```

The async client uses `httpx` under the hood.

## Scanning content

```python
result = client.scan("Check this content for threats")
print(result.verdict)   # "clean", "flag", "quarantine", "block"
print(result.findings)  # list of triggered rules
```

## Error handling

```python
from oktsec import PolicyError

try:
    result = client.send_message(
        to="researcher",
        content="hello",
    )
except PolicyError as e:
    print(e.status_code)                  # 403
    print(e.response.policy_decision)     # "acl_denied"
```
