# Bundled evaluation dataset — methodology & honest caveats

`bundled.jsonl` is a **small, synthetic, hand-labeled** dataset (18 records) used to prove the
evaluation harness *works* and to give a reproducible **illustrative floor** — it is **not** a
benchmark of real-world accuracy, and numbers from it must never be quoted as product accuracy.

## Construction

Each line is `{"id", "label", "alert"}`. The gold `label` is the intended verdict class:

- **malicious** (`m*`, `tp1`) — contain a known-bad indicator (reserved/documentation values:
  `198.51.100.23`, `203.0.113.66`, `*.example`, all-`a` hash) or clear malicious context.
- **suspicious** (`s*`) — threat keywords (ransomware, exploit, credential access, malware) without a
  hard indicator.
- **benign** (`b*`) — low severity + allowlisted/private infrastructure + routine markers
  (test/backup/update/training).
- **inconclusive** (`i*`) — ambiguous, medium severity, no decisive signal.
- **stealthy misses** (`fn1`, `fn2`) — real threats (labeled malicious/suspicious) **deliberately
  disguised** as benign (low severity, internal/allowlisted). These exist so the harness reports a
  **non-zero false-negative rate** — the metric the whole project is built to be honest about.

## What the harness reports

Threat-detection precision/recall/F1 (positive = malicious|suspicious), the **false-negative rate**,
exact verdict-class accuracy, calibration (Brier score + expected calibration error), and
cost-per-case. With the default **offline** provider the numbers measure the deterministic pipeline,
not model reasoning — they are labeled accordingly.

## Bring your own

Point the harness at your own labeled JSONL (same shape) with representative data from your
environment to get numbers that mean something for *you*. That is the only honest way to claim a
production figure.
