"""S3: Wazuh + Elastic adapters — OCSF mapping (unit) and read_alerts over mocked HTTP (respx)."""

from __future__ import annotations

import httpx
import respx

from blue_kakapo.connectors import (
    Capability,
    ElasticConnector,
    WazuhConnector,
    map_elastic_alert,
    map_wazuh_alert,
)
from blue_kakapo.schema.common import Severity
from blue_kakapo.schema.ocsf import ObservableType


def test_map_wazuh_alert() -> None:
    doc = {
        "rule": {
            "id": "5710",
            "level": 10,
            "description": "Attempt to login using a non-existent user",
            "mitre": {"id": ["T1110"]},
        },
        "agent": {"id": "001", "name": "web01", "ip": "10.0.0.5"},
        "data": {"srcip": "198.51.100.23", "srcuser": "root"},
    }
    alert = map_wazuh_alert(doc, tenant_id="t1")
    assert alert.severity == Severity.HIGH  # level 10 -> high
    assert alert.rule_id == "5710"
    assert alert.attack_techniques == ["T1110"]
    vals = {o.type: o.value for o in alert.events[0].observables}
    assert vals[ObservableType.IP] in ("10.0.0.5", "198.51.100.23")
    assert any(
        o.type == ObservableType.USER and o.contains_pii for o in alert.events[0].observables
    )


def test_map_elastic_alert() -> None:
    src = {
        "kibana": {
            "alert": {
                "rule": {
                    "name": "Malware Prevention Alert",
                    "threat": [{"technique": [{"id": "T1059"}]}],
                },
                "severity": "critical",
                "reason": "malware blocked",
            }
        },
        "host": {"name": "WS-9"},
        "source": {"ip": "203.0.113.66"},
        "user": {"name": "jdoe"},
    }
    alert = map_elastic_alert(src, tenant_id="t1")
    assert alert.severity == Severity.CRITICAL
    assert alert.rule_name == "Malware Prevention Alert"
    assert alert.attack_techniques == ["T1059"]
    assert any(
        o.type == ObservableType.USER and o.value == "jdoe" for o in alert.events[0].observables
    )


def test_connector_capability_declarations() -> None:
    wz = WazuhConnector(
        indexer_url="https://idx", manager_url="https://mgr", username="u", password="p"
    )
    el = ElasticConnector(es_url="https://es", kibana_url="https://kb", api_key="k")
    assert Capability.ACT in wz.info().capabilities
    assert any(s.verb == "firewall_drop" and s.reversible for s in wz.info().actions)
    assert any(
        s.verb == "isolate_host" and s.reverse_verb == "unisolate_host" for s in el.info().actions
    )


@respx.mock
async def test_wazuh_read_alerts_over_http() -> None:
    respx.post("https://idx/wazuh-alerts-*/_search").mock(
        return_value=httpx.Response(
            200,
            json={
                "hits": {
                    "hits": [
                        {
                            "_source": {
                                "rule": {"id": "100", "level": 12, "description": "Critical rule"},
                                "agent": {"name": "h1"},
                            }
                        }
                    ]
                }
            },
        )
    )
    wz = WazuhConnector(
        indexer_url="https://idx", manager_url="https://mgr", username="u", password="p"
    )
    alerts = await wz.read_alerts(tenant_id="t1")
    assert len(alerts) == 1 and alerts[0].severity == Severity.CRITICAL


@respx.mock
async def test_elastic_read_alerts_over_http() -> None:
    respx.post("https://es/.alerts-security.alerts-*/_search").mock(
        return_value=httpx.Response(
            200,
            json={
                "hits": {
                    "hits": [
                        {
                            "_source": {
                                "kibana": {
                                    "alert": {"rule": {"name": "Rule X"}, "severity": "high"}
                                },
                                "host": {"name": "h2"},
                            }
                        }
                    ]
                }
            },
        )
    )
    el = ElasticConnector(es_url="https://es", kibana_url="https://kb", api_key="k")
    alerts = await el.read_alerts(tenant_id="t1")
    assert (
        len(alerts) == 1 and alerts[0].severity == Severity.HIGH and alerts[0].rule_name == "Rule X"
    )
