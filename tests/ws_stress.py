from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from state_manager import agent_state


class FakeWebSocket:
    def __init__(self, fail: bool = False):
        self.fail = fail
        self.sent = 0

    async def send_json(self, data):
        if self.fail:
            raise RuntimeError("simulated client disconnect")
        self.sent += 1


async def main_async() -> int:
    clients = [FakeWebSocket() for _ in range(50)] + [FakeWebSocket(fail=True) for _ in range(10)]
    with agent_state.ws_lock:
        agent_state.ws_clients.update(clients)
    for index in range(100):
        await agent_state._broadcast({"type": "decision", "data": {"seq": index}})
    with agent_state.ws_lock:
        remaining = len(agent_state.ws_clients)
    ok = remaining == 50 and all(client.sent == 100 for client in clients[:50])
    print(json.dumps({"remaining_clients": remaining, "ok": ok}, indent=2))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main_async()))
