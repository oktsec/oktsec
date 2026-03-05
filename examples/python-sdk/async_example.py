#!/usr/bin/env python3
"""Async oktsec Python SDK example.

Prerequisites:
    pip install oktsec

    # Start oktsec:
    oktsec setup
    oktsec serve --config oktsec.yaml
"""

import asyncio

from oktsec import AsyncClient, PolicyError, generate_keypair


async def main():
    kp = generate_keypair("async-agent")

    async with AsyncClient("http://localhost:8080", "async-agent", keypair=kp) as c:
        # Health check
        health = await c.health()
        print(f"Proxy: {health.status} (v{health.version})")

        # Send multiple messages concurrently
        messages = [
            ("agent-a", "Analyze this dataset"),
            ("agent-b", "Summarize the results"),
            ("agent-c", "Generate a report"),
        ]

        tasks = [c.send_message(to, content) for to, content in messages]

        for coro in asyncio.as_completed(tasks):
            try:
                resp = await coro
                print(f"  {resp.message_id}: {resp.status}")
            except PolicyError as e:
                print(f"  Rejected: {e.response.policy_decision}")


if __name__ == "__main__":
    asyncio.run(main())
