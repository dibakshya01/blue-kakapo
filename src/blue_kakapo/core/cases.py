"""Case repository — (de)serialize `Case` models through the store's JSON document table."""

from __future__ import annotations

from ..schema.common import utcnow
from ..schema.models import Case
from .store import Store


class CaseRepo:
    def __init__(self, store: Store) -> None:
        self.store = store

    def save(self, case: Case) -> Case:
        case.updated_at = utcnow()
        self.store.upsert_case(
            {
                "id": case.id,
                "tenant_id": case.tenant_id,
                "state": case.state,
                "severity": case.severity,
                "title": case.title,
                "updated_at": case.updated_at,
                "data": case.model_dump(mode="json"),
            }
        )
        return case

    def get(self, case_id: str) -> Case | None:
        row = self.store.get_case(case_id)
        return Case.model_validate(row["data"]) if row else None

    def list(self, tenant_id: str, limit: int = 100) -> list[Case]:
        rows = self.store.list_cases(tenant_id, limit=limit)
        return [Case.model_validate(r["data"]) for r in rows]
