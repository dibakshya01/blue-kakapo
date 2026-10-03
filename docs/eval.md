# Evaluation harness

The harness measures triage quality **honestly** — including the metric that matters most and is most
often hidden: the **false-negative rate** (real threats triaged as benign).

```bash
uv run bk eval                        # bundled dataset, current provider
uv run bk eval --dataset mine.jsonl   # your labeled data
uv run bk eval --json                 # machine-readable report
```

Also available at `GET /api/eval` and the dashboard's Settings tab.

## What it reports
- threat **precision / recall / F1** (positive = malicious|suspicious)
- **false-negative rate** + the ids it missed
- exact **verdict accuracy**
- **calibration** — Brier score + expected calibration error (ECE)
- **cost per case** (USD) — backs the "predictable cost" claim

## Honesty rules
- With the **offline** provider the numbers measure the deterministic pipeline, not model reasoning —
  the report labels them an **illustrative floor**, never a real-world claim.
- The bundled dataset (`src/blue_kakapo/eval/datasets/`) is small, synthetic, and documented, and
  **deliberately includes stealthy misses** so the FNR is non-zero. See its README.
- For numbers that mean something for *you*, run the harness on your own labeled JSONL
  (`{"id","label","alert"}`) with a named, pinned model. That is the only honest way to claim a figure.
