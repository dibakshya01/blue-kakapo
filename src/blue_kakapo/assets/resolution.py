"""Deterministic entity resolution.

A first-pass, deterministic stitching of observables into case entities, matched to inventory assets
by exact identifier. Each merge carries an explicit confidence; ambiguous/unknown mappings are left
unresolved rather than guessed. Probabilistic/ML stitching is an explicit non-goal for v1.
"""

from __future__ import annotations

from ..schema.models import Case, Entity
from ..schema.ocsf import ObservableType
from .inventory import AssetInventory

# Observable types that represent an actor/asset worth resolving.
_ENTITY_TYPES = {
    ObservableType.IP: "ip",
    ObservableType.HOSTNAME: "host",
    ObservableType.FQDN: "host",
    ObservableType.USER: "user",
}


def resolve_entities(case: Case, inventory: AssetInventory) -> list[Entity]:
    """Return deduped entities for a case, linked to inventory assets by exact identifier."""
    seen: dict[tuple[str, str], Entity] = {}
    for alert in case.alerts:
        for event in alert.events:
            for obs in event.observables:
                etype = _ENTITY_TYPES.get(obs.type)
                if etype is None:
                    continue
                key = (etype, obs.value)
                if key in seen:
                    continue
                asset = inventory.find_by_identifier(case.tenant_id, obs.value)
                seen[key] = Entity(
                    type=etype,
                    value=obs.value,
                    identifiers=[obs.value],
                    asset_id=asset.id if asset else None,
                    resolution_confidence=1.0 if asset else 0.5,
                )
    return list(seen.values())
