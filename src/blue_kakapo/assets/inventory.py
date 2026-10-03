"""Asset inventory — the source of truth for asset criticality that drives Guardian blast-radius rules.

Populated from connector data, CMDB import, or manual tagging. Unknown assets default to a
conservative ``normal`` criticality; the Guardian treats ``critical``/``crown_jewel`` specially.
"""

from __future__ import annotations

from ..core.store import Store
from ..schema.common import AssetCriticality
from ..schema.models import AssetRecord


class AssetInventory:
    def __init__(self, store: Store) -> None:
        self.store = store

    def upsert(self, asset: AssetRecord) -> AssetRecord:
        identifiers = list(dict.fromkeys([asset.name, *asset.identifiers]))
        self.store.upsert_asset(
            {
                "id": asset.id,
                "tenant_id": asset.tenant_id,
                "name": asset.name,
                "criticality": asset.criticality,
                "data": asset.model_dump(mode="json"),
            },
            identifiers=identifiers,
        )
        return asset

    def get(self, asset_id: str) -> AssetRecord | None:
        row = self.store.get_asset(asset_id)
        return AssetRecord.model_validate(row["data"]) if row else None

    def find_by_identifier(self, tenant_id: str, identifier: str) -> AssetRecord | None:
        row = self.store.find_asset_by_identifier(tenant_id, identifier)
        return AssetRecord.model_validate(row["data"]) if row else None

    def list(self, tenant_id: str) -> list[AssetRecord]:
        return [AssetRecord.model_validate(r["data"]) for r in self.store.list_assets(tenant_id)]

    def criticality_for(self, tenant_id: str, identifier: str) -> str:
        asset = self.find_by_identifier(tenant_id, identifier)
        return asset.criticality if asset else AssetCriticality.NORMAL
