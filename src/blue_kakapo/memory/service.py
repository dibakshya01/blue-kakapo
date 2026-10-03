"""MemoryService — compaction, opt-in hybrid recall, and poisoning defenses.

- **remember(case):** compacts a resolved case into a `MemoryRecord` (summary + features + metadata +
  embedding), authored by an agent and therefore **quarantined** by default (ASI06).
- **recall(...):** opt-in per case. Blends dense similarity with a lexical bonus, weights by
  **trust tier** and **decay**, and **excludes quarantined** (agent-authored, un-reviewed) records —
  so a poisoned "past case" can't steer a verdict until a human promotes it.
- **promote / reembed:** humans promote records to `reviewed`; changing the embedding model is detected
  and triggers a re-embed migration (mixing vectors from different models is meaningless).
"""

from __future__ import annotations

from ..providers import ProviderGateway
from ..schema.common import MemoryTrustTier
from ..schema.models import Case, MemoryRecord
from .base import MemoryBackend, ScoredRecord, lexical_overlap

# Retrieval weight by trust tier; 0.0 == excluded from decisioning.
_TRUST_WEIGHT = {
    MemoryTrustTier.QUARANTINED: 0.0,
    MemoryTrustTier.AGENT: 0.5,
    MemoryTrustTier.REVIEWED: 1.0,
    MemoryTrustTier.AUTHORITATIVE: 1.2,
}


def compact_case(case: Case) -> str:
    """A short, embeddable summary of a resolved case."""
    v = case.verdict
    parts = [case.title, f"severity={case.severity}"]
    if v:
        parts.append(f"verdict={v.verdict_class} routing={v.routing}")
        if v.rationale:
            parts.append(v.rationale)
    if case.attack_techniques:
        parts.append("techniques=" + ",".join(case.attack_techniques))
    for ev in case.evidence[:5]:
        parts.append(ev.summary)
    return " | ".join(parts)


def case_query_text(case: Case) -> str:
    """Text used to find similar past cases for an incoming case."""
    obs = [o.value for a in case.alerts for e in a.events for o in e.observables]
    return " ".join([case.title, *case.attack_techniques, *obs[:10]])


class MemoryService:
    def __init__(self, backend: MemoryBackend, gateway: ProviderGateway) -> None:
        self.backend = backend
        self.gateway = gateway

    async def remember(
        self, case: Case, *, outcome: str | None = None, author: str = "agent"
    ) -> MemoryRecord:
        summary = compact_case(case)
        embedding = (await self.gateway.embed([summary]))[0]
        v = case.verdict
        metadata = {
            "technique": case.attack_techniques[0] if case.attack_techniques else "",
            "severity": case.severity,
            "outcome": outcome or case.state,
            "verdict_class": v.verdict_class if v else "",
        }
        record = MemoryRecord(
            tenant_id=case.tenant_id,
            case_id=case.id,
            case_summary=summary,
            features={"severity": case.severity, "routing": v.routing if v else None},
            metadata=metadata,
            embedding=embedding,
            embedding_model=self.gateway.embedding_model_id(),
            embedding_version=self.gateway.embedding_model_id(),
            provenance=author,
            trust_tier=MemoryTrustTier.QUARANTINED,  # agent-authored: not usable until promoted
        )
        await self.backend.upsert(record)
        return record

    def needs_reembed(self, record: MemoryRecord) -> bool:
        return record.embedding_model != self.gateway.embedding_model_id()

    async def forget_case(self, tenant_id: str, case_id: str) -> int:
        """Delete every memory record derived from a case (for GDPR erasure). Returns the count."""
        return await self.backend.delete_by_case(tenant_id, case_id)

    async def recall(
        self,
        tenant_id: str,
        query_text: str,
        *,
        k: int = 5,
        filters: dict[str, str] | None = None,
        use_memory: bool = True,
    ) -> list[ScoredRecord]:
        if not use_memory or not query_text.strip():
            return []
        embedding = (await self.gateway.embed([query_text]))[0]
        candidates = await self.backend.search(
            tenant_id=tenant_id, embedding=embedding, k=k * 4, metadata_filters=filters
        )
        current_model = self.gateway.embedding_model_id()
        out: list[ScoredRecord] = []
        for cand in candidates:
            rec = cand.record
            trust = _TRUST_WEIGHT.get(rec.trust_tier, 0.0)
            if trust <= 0.0:
                continue  # quarantined / untrusted -> excluded from decisioning
            if rec.embedding_model != current_model:
                continue  # stale embedding (model changed) -> excluded; run reembed()
            lexical = lexical_overlap(query_text, rec.case_summary)
            score = cand.score * trust * rec.decay * (1.0 + 0.5 * lexical)
            out.append(ScoredRecord(rec, score))
        out.sort(key=lambda s: s.score, reverse=True)
        return out[:k]

    async def recall_for_case(
        self, case: Case, *, k: int = 5, use_memory: bool | None = None
    ) -> list[ScoredRecord]:
        enabled = case.memory_enabled if use_memory is None else use_memory
        return await self.recall(case.tenant_id, case_query_text(case), k=k, use_memory=enabled)

    async def promote(
        self, tenant_id: str, record_id: str, tier: str = MemoryTrustTier.REVIEWED
    ) -> MemoryRecord | None:
        rec = await self.backend.get(tenant_id, record_id)
        if rec is None:
            return None
        rec.trust_tier = tier
        rec.provenance = f"{rec.provenance}+promoted"
        await self.backend.upsert(rec)
        return rec

    async def reembed(self, tenant_id: str) -> int:
        """Re-embed records whose embedding model no longer matches the active one. Returns count."""
        count = 0
        for rec in await self.backend.all(tenant_id):
            if self.needs_reembed(rec):
                rec.embedding = (await self.gateway.embed([rec.case_summary]))[0]
                rec.embedding_model = self.gateway.embedding_model_id()
                rec.embedding_version = self.gateway.embedding_model_id()
                await self.backend.upsert(rec)
                count += 1
        return count
