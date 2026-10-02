"""A small in-process async pub/sub event bus.

Used to decouple the kernel from consumers (the WebSocket live stream, metrics, etc.). Default is
in-process; a durable/distributed transport (Redis Streams / NATS) can implement the same surface
later for multi-node deployments. Events are tenant-scoped.
"""

from __future__ import annotations

import asyncio
import contextlib
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from typing import Any

from ..schema.common import utcnow


@dataclass
class Event:
    topic: str
    tenant_id: str
    payload: dict[str, Any] = field(default_factory=dict)
    ts: str = field(default_factory=lambda: utcnow().isoformat())


class EventBus:
    """Fan-out pub/sub. Subscribers receive events matching a topic prefix and (optionally) tenant."""

    def __init__(self, max_queue: int = 1000) -> None:
        self._subscribers: list[tuple[str, str | None, asyncio.Queue[Event]]] = []
        self._max_queue = max_queue

    async def publish(self, event: Event) -> None:
        for prefix, tenant, queue in list(self._subscribers):
            if not event.topic.startswith(prefix):
                continue
            if tenant is not None and tenant != event.tenant_id:
                continue
            with contextlib.suppress(asyncio.QueueFull):
                queue.put_nowait(event)  # drop on backpressure rather than block the producer

    @contextlib.asynccontextmanager
    async def subscribe(
        self, topic_prefix: str = "", tenant_id: str | None = None
    ) -> AsyncIterator[asyncio.Queue[Event]]:
        queue: asyncio.Queue[Event] = asyncio.Queue(maxsize=self._max_queue)
        sub = (topic_prefix, tenant_id, queue)
        self._subscribers.append(sub)
        try:
            yield queue
        finally:
            self._subscribers.remove(sub)

    @property
    def subscriber_count(self) -> int:
        return len(self._subscribers)
