# observability/channels/sse.py
"""
Server-Sent Events backend.

Each logged-in user can have multiple open streams (dashboard tab + companion
app). For each user we keep a list of bounded asyncio.Queues; broadcasting to
the user fans out across every connected queue.

This is the only channel that doesn't go anywhere external — it just pushes
into in-process queues that the /notifications/stream route drains.
"""

import asyncio
import json
import time
from collections import defaultdict
from typing import Any

from shared.logging import get_logger

logger = get_logger("observability.channels.sse")


class SSEBackend:

    def __init__(self, max_buffer: int = 200):
        self._max_buffer = max_buffer
        self._queues: dict[str, list[asyncio.Queue]] = defaultdict(list)

    # ── Connection management ─────────────────────────────────────────────

    def connect(self, username: str) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=self._max_buffer)
        self._queues[username].append(q)
        logger.info("SSE client connected", username=username,
                    total_for_user=len(self._queues[username]))
        return q

    def disconnect(self, username: str, q: asyncio.Queue) -> None:
        if username in self._queues:
            try:
                self._queues[username].remove(q)
            except ValueError:
                pass
            if not self._queues[username]:
                del self._queues[username]

    # ── Dispatch ───────────────────────────────────────────────────────────

    async def send(self, notif: dict, user: Any) -> tuple[bool, str]:
        """Push a notification payload to every open stream for this user."""
        username = user.username if hasattr(user, "username") else str(user)
        queues = list(self._queues.get(username, []))
        if not queues:
            return (False, "no open stream")
        delivered = 0
        for q in queues:
            try:
                q.put_nowait(notif)
                delivered += 1
            except asyncio.QueueFull:
                # Drop oldest, push newest. Better than dropping the page.
                try:
                    q.get_nowait()
                    q.put_nowait(notif)
                    delivered += 1
                except Exception:
                    pass
        return (delivered > 0, f"sent to {delivered} stream(s)")

    def connected_users(self) -> dict[str, int]:
        return {u: len(qs) for u, qs in self._queues.items()}
