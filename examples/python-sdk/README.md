# Python SDK Examples

## Setup

```bash
# Install the SDK
pip install oktsec

# Start oktsec (if not already running)
oktsec setup
oktsec serve --config oktsec.yaml
```

## Run

```bash
# Basic sync example
python example.py

# Async concurrent example
python async_example.py
```

## Expected output

```
Generated keypair for example-agent
Proxy status: ok (v0.8.0)
Message abc-123: delivered
  Verified sender: True
  Policy: allow
Blocked (expected): content_blocked
  Rule: IAP-001 - Prompt Injection (critical)
```
