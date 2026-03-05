"""Sync and async HTTP clients for the oktsec proxy."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import httpx

from oktsec.models import (
    HealthResponse,
    MessageResponse,
    PolicyError,
)
from oktsec.signing import Keypair


class Client:
    """Synchronous client for the oktsec security proxy.

    Usage::

        from oktsec import Client

        c = Client("http://localhost:8080", "my-agent")
        resp = c.send_message("recipient", "hello")
        print(resp.status, resp.message_id)

    With signing::

        from oktsec import Client, load_keypair

        kp = load_keypair("./keys", "my-agent")
        c = Client("http://localhost:8080", "my-agent", keypair=kp)
        resp = c.send_message("recipient", "hello")
    """

    def __init__(
        self,
        base_url: str,
        agent_name: str,
        keypair: Keypair | None = None,
        timeout: float = 30.0,
    ):
        self.base_url = base_url.rstrip("/")
        self.agent_name = agent_name
        self.keypair = keypair
        self._client = httpx.Client(timeout=timeout)

    def send_message(
        self,
        to: str,
        content: str,
        metadata: dict[str, str] | None = None,
    ) -> MessageResponse:
        """Send a message to another agent through the proxy.

        Raises :class:`PolicyError` for non-200 responses (blocked, quarantined,
        rate-limited, etc.).
        """
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        payload: dict[str, Any] = {
            "from": self.agent_name,
            "to": to,
            "content": content,
            "timestamp": ts,
        }

        if self.keypair:
            payload["signature"] = self.keypair.sign_message(
                self.agent_name, to, content, ts
            )

        if metadata:
            payload["metadata"] = metadata

        resp = self._client.post(
            f"{self.base_url}/v1/message",
            json=payload,
            headers={"Content-Type": "application/json"},
        )

        msg_resp = MessageResponse.from_dict(resp.json())

        if resp.status_code != 200:
            raise PolicyError(resp.status_code, msg_resp)

        return msg_resp

    def health(self) -> HealthResponse:
        """Check the proxy health endpoint."""
        resp = self._client.get(f"{self.base_url}/health")
        resp.raise_for_status()
        data = resp.json()
        return HealthResponse(status=data["status"], version=data["version"])

    def get_quarantine(self, quarantine_id: str) -> dict:
        """Fetch a quarantined message by ID."""
        resp = self._client.get(
            f"{self.base_url}/v1/quarantine/{quarantine_id}"
        )
        resp.raise_for_status()
        return resp.json()

    def close(self) -> None:
        """Close the underlying HTTP client."""
        self._client.close()

    def __enter__(self) -> Client:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()


class AsyncClient:
    """Asynchronous client for the oktsec security proxy.

    Usage::

        import asyncio
        from oktsec import AsyncClient

        async def main():
            async with AsyncClient("http://localhost:8080", "my-agent") as c:
                resp = await c.send_message("recipient", "hello")
                print(resp.status)

        asyncio.run(main())
    """

    def __init__(
        self,
        base_url: str,
        agent_name: str,
        keypair: Keypair | None = None,
        timeout: float = 30.0,
    ):
        self.base_url = base_url.rstrip("/")
        self.agent_name = agent_name
        self.keypair = keypair
        self._client = httpx.AsyncClient(timeout=timeout)

    async def send_message(
        self,
        to: str,
        content: str,
        metadata: dict[str, str] | None = None,
    ) -> MessageResponse:
        """Send a message to another agent through the proxy."""
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        payload: dict[str, Any] = {
            "from": self.agent_name,
            "to": to,
            "content": content,
            "timestamp": ts,
        }

        if self.keypair:
            payload["signature"] = self.keypair.sign_message(
                self.agent_name, to, content, ts
            )

        if metadata:
            payload["metadata"] = metadata

        resp = await self._client.post(
            f"{self.base_url}/v1/message",
            json=payload,
            headers={"Content-Type": "application/json"},
        )

        msg_resp = MessageResponse.from_dict(resp.json())

        if resp.status_code != 200:
            raise PolicyError(resp.status_code, msg_resp)

        return msg_resp

    async def health(self) -> HealthResponse:
        """Check the proxy health endpoint."""
        resp = await self._client.get(f"{self.base_url}/health")
        resp.raise_for_status()
        data = resp.json()
        return HealthResponse(status=data["status"], version=data["version"])

    async def get_quarantine(self, quarantine_id: str) -> dict:
        """Fetch a quarantined message by ID."""
        resp = await self._client.get(
            f"{self.base_url}/v1/quarantine/{quarantine_id}"
        )
        resp.raise_for_status()
        return resp.json()

    async def close(self) -> None:
        """Close the underlying HTTP client."""
        await self._client.aclose()

    async def __aenter__(self) -> AsyncClient:
        return self

    async def __aexit__(self, *args: object) -> None:
        await self.close()
