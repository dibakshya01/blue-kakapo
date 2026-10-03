"""S4: asset inventory + deterministic entity resolution."""

from __future__ import annotations

from blue_kakapo.assets import AssetInventory, resolve_entities
from blue_kakapo.core import Store
from blue_kakapo.normalize import normalize_alert
from blue_kakapo.schema.models import AssetRecord, Case


def _inv() -> AssetInventory:
    return AssetInventory(Store.in_memory())


def test_inventory_upsert_and_lookup() -> None:
    inv = _inv()
    inv.upsert(
        AssetRecord(
            tenant_id="t1",
            name="dc01",
            identifiers=["10.0.0.1", "DC01.corp"],
            criticality="crown_jewel",
        )
    )
    assert inv.criticality_for("t1", "10.0.0.1") == "crown_jewel"
    assert inv.criticality_for("t1", "DC01.corp") == "crown_jewel"
    assert inv.criticality_for("t1", "unknown-host") == "normal"  # conservative default
    assert inv.find_by_identifier("t1", "dc01").name == "dc01"


def test_inventory_is_tenant_scoped() -> None:
    inv = _inv()
    inv.upsert(AssetRecord(tenant_id="t1", name="h", identifiers=["1.2.3.4"], criticality="high"))
    assert inv.find_by_identifier("t2", "1.2.3.4") is None


def test_entity_resolution_links_assets() -> None:
    inv = _inv()
    inv.upsert(
        AssetRecord(tenant_id="t1", name="web01", identifiers=["10.0.0.5"], criticality="high")
    )
    alert = normalize_alert({"title": "x", "src_ip": "10.0.0.5", "user": "jdoe"}, tenant_id="t1")
    case = Case(tenant_id="t1", title="x", alerts=[alert])
    entities = resolve_entities(case, inv)
    by_val = {e.value: e for e in entities}
    assert by_val["10.0.0.5"].asset_id is not None  # resolved to the asset
    assert by_val["10.0.0.5"].resolution_confidence == 1.0
    assert by_val["jdoe"].asset_id is None  # unresolved -> lower confidence, not guessed
    assert by_val["jdoe"].resolution_confidence == 0.5
