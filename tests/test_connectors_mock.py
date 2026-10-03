"""S3: mock connectors + registry — the capability-declaring contract."""

from __future__ import annotations

import pytest

from blue_kakapo.connectors import (
    Capability,
    ConnectorError,
    ConnectorRegistry,
    MockEDR,
    MockSIEM,
)
from blue_kakapo.schema.actions import Action
from blue_kakapo.schema.ocsf import Observable, ObservableType


async def test_mock_siem_reads_and_queries() -> None:
    siem = MockSIEM()
    info = siem.info()
    assert Capability.READ_ALERTS in info.capabilities and info.supports_native_query
    alerts = await siem.read_alerts(tenant_id="t1")
    assert len(alerts) == 3
    assert all(a.tenant_id == "t1" and a.events for a in alerts)
    q = await siem.query(tenant_id="t1", native_query="rule.level:>=10")
    assert q.count == 1 and q.rows[0]["query"] == "rule.level:>=10"  # native-query escape hatch


async def test_mock_siem_enrich() -> None:
    ev = await MockSIEM().enrich(
        tenant_id="t1", observable=Observable(type=ObservableType.IP, value="10.0.0.5")
    )
    assert len(ev) == 1 and ev[0].connector == "mock-siem"


async def test_mock_edr_isolate_is_reversible_and_stateful() -> None:
    edr = MockEDR()
    res = await edr.act(Action(tenant_id="t1", verb="isolate_host", target="host-1"))
    assert res.status == "ok" and res.reversible is True
    assert "host-1" in edr.isolated_hosts
    # reverse it
    await edr.act(Action(tenant_id="t1", verb="unisolate_host", target="host-1"))
    assert "host-1" not in edr.isolated_hosts


async def test_mock_edr_dry_run_changes_nothing() -> None:
    edr = MockEDR()
    res = await edr.act(Action(tenant_id="t1", verb="isolate_host", target="h2"), dry_run=True)
    assert res.status == "dry_run"
    assert "h2" not in edr.isolated_hosts


async def test_mock_edr_idempotency() -> None:
    edr = MockEDR()
    a = Action(tenant_id="t1", verb="block_ioc", target="198.51.100.23", idempotency_key="k1")
    r1 = await edr.act(a)
    r2 = await edr.act(
        Action(tenant_id="t1", verb="block_ioc", target="198.51.100.23", idempotency_key="k1")
    )
    assert r1.idempotency_key == r2.idempotency_key == "k1"
    assert len(edr.action_log) == 1  # applied once


async def test_mock_edr_kill_process_is_irreversible_and_unknown_rejected() -> None:
    edr = MockEDR()
    spec = next(s for s in edr.info().actions if s.verb == "kill_process")
    assert spec.reversible is False
    with pytest.raises(ConnectorError):
        await edr.act(Action(tenant_id="t1", verb="nuke_everything", target="x"))


def test_registry_capability_and_action_lookup() -> None:
    reg = ConnectorRegistry()
    reg.register(MockSIEM())
    reg.register(MockEDR())
    assert len(reg.with_capability(Capability.READ_ALERTS)) == 1
    assert len(reg.with_capability(Capability.ACT)) == 1
    found = reg.find_action("isolate_host")
    assert found is not None and found[0].info().name == "mock-edr"
    assert reg.find_action("does_not_exist") is None
