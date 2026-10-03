"""S6: the evaluation harness — honest metrics incl. the false-negative rate."""

from __future__ import annotations

from blue_kakapo.config import ProviderKind, Settings
from blue_kakapo.eval import load_dataset, run_eval
from blue_kakapo.providers import ProviderGateway


def test_bundled_dataset_loads() -> None:
    rows = load_dataset()
    assert len(rows) >= 15
    assert all("label" in r and "alert" in r for r in rows)


async def test_run_eval_offline_reports_false_negative_rate() -> None:
    gw = ProviderGateway(Settings(provider=ProviderKind.OFFLINE))
    report = await run_eval(gateway=gw)
    assert report.provider == "offline"
    assert report.illustrative_only is True  # must be labeled as a floor, not a real-world claim
    # The dataset contains deliberately-stealthy misses, so FNR must be > 0 (honesty check).
    assert report.false_negative_rate > 0.0
    assert report.missed_ids  # names the missed cases
    # Sanity on the detection metrics.
    assert 0.0 <= report.precision <= 1.0
    assert 0.0 <= report.recall <= 1.0
    assert report.n >= 15


async def test_eval_report_render_mentions_fnr_and_floor() -> None:
    report = await run_eval(gateway=ProviderGateway(Settings(provider=ProviderKind.OFFLINE)))
    text = report.render()
    assert "FALSE-NEGATIVE RATE" in text
    assert "ILLUSTRATIVE FLOOR" in text
