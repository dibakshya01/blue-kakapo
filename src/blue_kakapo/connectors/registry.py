"""A small registry of connector instances, keyed by name, with capability lookups."""

from __future__ import annotations

from .base import Capability, Connector, ConnectorInfo


class ConnectorRegistry:
    def __init__(self) -> None:
        self._connectors: dict[str, Connector] = {}

    def register(self, connector: Connector) -> None:
        self._connectors[connector.info().name] = connector

    def get(self, name: str) -> Connector | None:
        return self._connectors.get(name)

    def all(self) -> list[Connector]:
        return list(self._connectors.values())

    def with_capability(self, capability: Capability) -> list[Connector]:
        return [c for c in self._connectors.values() if capability in c.info().capabilities]

    def info(self) -> list[ConnectorInfo]:
        return [c.info() for c in self._connectors.values()]

    def find_action(self, verb: str) -> tuple[Connector, str] | None:
        """Return (connector, verb) for the first connector that declares an action verb."""
        for c in self._connectors.values():
            for spec in c.info().actions:
                if spec.verb == verb:
                    return c, verb
        return None
