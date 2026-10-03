"""The evaluation harness — the honesty centerpiece.

Runs the triage pipeline over a labeled dataset and reports threat-detection precision/recall/F1, the
**false-negative rate** (real threats triaged as benign — the scary metric), exact verdict-class
accuracy, calibration (Brier + ECE), and cost-per-case. Published numbers must come from a **named,
pinned model** with a documented dataset; the default offline provider yields an *illustrative floor*
(it measures the deterministic pipeline, not model reasoning), and the report says so.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from ..agents.l1 import triage
from ..normalize import normalize_alert
from ..providers import ProviderGateway
from ..schema.models import Case

_BUNDLED = Path(__file__).parent / "datasets" / "bundled.jsonl"
_THREAT_CLASSES = {"malicious", "suspicious"}


@dataclass
class EvalReport:
    n: int
    provider: str
    model: str
    illustrative_only: bool
    true_pos: int
    false_pos: int
    true_neg: int
    false_neg: int
    precision: float
    recall: float
    f1: float
    false_negative_rate: float
    verdict_accuracy: float
    brier_score: float
    expected_calibration_error: float
    avg_cost_usd: float
    missed_ids: list[str] = field(default_factory=list)
    note: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def render(self) -> str:
        lines = [
            "blue-kakapo evaluation report",
            f"  dataset size        : {self.n}",
            f"  provider / model    : {self.provider} / {self.model}",
            f"  threat precision    : {self.precision:.3f}",
            f"  threat recall       : {self.recall:.3f}",
            f"  threat F1           : {self.f1:.3f}",
            f"  FALSE-NEGATIVE RATE : {self.false_negative_rate:.3f}  (missed: {', '.join(self.missed_ids) or 'none'})",
            f"  verdict accuracy    : {self.verdict_accuracy:.3f}",
            f"  Brier score         : {self.brier_score:.3f}  (lower is better)",
            f"  calibration (ECE)   : {self.expected_calibration_error:.3f}  (lower is better)",
            f"  avg cost / case     : ${self.avg_cost_usd:.4f}",
        ]
        if self.illustrative_only:
            lines.append(
                "  NOTE: offline/deterministic provider — ILLUSTRATIVE FLOOR, not a model-accuracy or "
                "real-world claim. Run with a named model on your own data for a meaningful figure."
            )
        return "\n".join(lines)


def load_dataset(path: str | Path | None = None) -> list[dict[str, Any]]:
    p = Path(path) if path else _BUNDLED
    return [json.loads(line) for line in p.read_text(encoding="utf-8").splitlines() if line.strip()]


def _ece(confidences: list[float], correct: list[int], bins: int = 10) -> float:
    if not confidences:
        return 0.0
    total = len(confidences)
    ece = 0.0
    for b in range(bins):
        lo, hi = b / bins, (b + 1) / bins
        idx = [i for i, c in enumerate(confidences) if (c > lo or (b == 0 and c == 0)) and c <= hi]
        if not idx:
            continue
        avg_conf = sum(confidences[i] for i in idx) / len(idx)
        acc = sum(correct[i] for i in idx) / len(idx)
        ece += (len(idx) / total) * abs(avg_conf - acc)
    return ece


async def run_eval(
    *, dataset: str | Path | None = None, gateway: ProviderGateway | None = None
) -> EvalReport:
    gw = gateway or ProviderGateway()
    records = load_dataset(dataset)
    illustrative = gw.provider_name == "offline"

    tp = fp = tn = fn = 0
    exact = 0
    missed: list[str] = []
    briers: list[float] = []
    confs: list[float] = []
    correct_flags: list[int] = []
    total_cost = 0.0

    for rec in records:
        gold = rec["label"]
        gold_threat = gold in _THREAT_CLASSES
        alert = normalize_alert(rec["alert"], tenant_id="eval")
        case = Case(tenant_id="eval", title=alert.title, severity=alert.severity, alerts=[alert])
        verdict, _evidence, model_ref = await triage(case, gw)
        pred_threat = verdict.verdict_class in _THREAT_CLASSES
        if model_ref is not None:
            total_cost += model_ref.usd

        if gold_threat and pred_threat:
            tp += 1
        elif gold_threat and not pred_threat:
            fn += 1
            missed.append(rec["id"])
        elif not gold_threat and pred_threat:
            fp += 1
        else:
            tn += 1

        if verdict.verdict_class == gold:
            exact += 1

        # Calibration of P(threat).
        p_threat = verdict.confidence if pred_threat else (1.0 - verdict.confidence)
        y = 1 if gold_threat else 0
        briers.append((p_threat - y) ** 2)
        confs.append(p_threat)
        correct_flags.append(1 if (pred_threat == gold_threat) else 0)

    n = len(records)
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    fnr = fn / (tp + fn) if (tp + fn) else 0.0
    brier = sum(briers) / len(briers) if briers else 0.0

    return EvalReport(
        n=n,
        provider=gw.provider_name,
        model=gw.model,
        illustrative_only=illustrative,
        true_pos=tp,
        false_pos=fp,
        true_neg=tn,
        false_neg=fn,
        precision=round(precision, 3),
        recall=round(recall, 3),
        f1=round(f1, 3),
        false_negative_rate=round(fnr, 3),
        verdict_accuracy=round(exact / n, 3) if n else 0.0,
        brier_score=round(brier, 3),
        expected_calibration_error=round(_ece(confs, correct_flags), 3),
        avg_cost_usd=round(total_cost / n, 4) if n else 0.0,
        missed_ids=missed,
        note="illustrative floor" if illustrative else "model-based",
    )
