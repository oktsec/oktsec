# Installation

## Quick install

```bash
curl -fsSL https://raw.githubusercontent.com/oktsec/oktsec/main/install.sh | bash
```

Installs the latest binary to `~/.local/bin`. Customize with environment variables:

```bash
VERSION=v0.12.0 curl -fsSL https://raw.githubusercontent.com/oktsec/oktsec/main/install.sh | bash
INSTALL_DIR=/usr/local/bin curl -fsSL https://raw.githubusercontent.com/oktsec/oktsec/main/install.sh | bash
```

## Pre-built binaries

Download from the [releases page](https://github.com/oktsec/oktsec/releases). Available for Linux, macOS, and Windows on amd64 and arm64.

## From source

```bash
go install github.com/oktsec/oktsec/cmd/oktsec@latest
```

Requires Go 1.23+.

## Docker

```bash
docker pull ghcr.io/oktsec/oktsec:latest
docker run -p 8080:8080 ghcr.io/oktsec/oktsec
```

With config and key persistence:

```bash
docker run -p 8080:8080 \
  -v ./oktsec.yaml:/home/oktsec/oktsec.yaml \
  -v ./keys:/home/oktsec/keys \
  -v oktsec-data:/home/oktsec/data \
  ghcr.io/oktsec/oktsec serve --config /home/oktsec/oktsec.yaml
```

Docker Compose (recommended for multi-agent setups):

```bash
docker compose up -d
```

## Verify installation

```bash
oktsec version
oktsec verify --config oktsec.yaml
```
