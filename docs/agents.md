# The agent roster

14 specialized agents + a deterministic orchestrator. Every agent declares an **AgBOM** (tools, models,
connectors, data scopes, permissions), an **autonomy level**, and satisfies the **Rule of Two**
(construction fails otherwise). All are read/propose-only except RESP; all write to the ledger.

| Agent | Role | Autonomy | Breaks which R2 leg |
|-------|------|----------|---------------------|
| **L1** | Triage & intake — evidence-cited verdict | propose | no sensitive access, no state change |
| **WATCH** | Early warning — bursts/anomalies | propose | no sensitive access, no state change |
| **L2** | Investigation — connector enrich + SIEM query | propose | no state change |
| **FUSION** | Links signals & campaigns (entity overlap) | propose | no sensitive access, no state change |
| **INTEL** | Adversary context — IOC intel + ATT&CK tactics | propose | no sensitive access, no state change |
| **HUNT** | Proactive hunting — hypothesis → query | propose | no state change |
| **DET** | Detection engineering — coverage gaps + Sigma draft | propose | no untrusted input |
| **VULN** | Exposure management — KEV/CVSS × asset × threat | propose | no untrusted input |
| **INSIDER** | Insider risk — privacy-gated UEBA signal | propose | no state change |
| **RESP** | Containment — **Guardian-gated, human-approved** | act-on-approval | **no untrusted input** |
| **COMMS** | Keeps you informed — summaries + drafted external msgs | propose | all three broken |
| **RPT** | Reporting & insight — incident/compliance/metrics | propose | no untrusted input, no state change |
| **MAINT** | Keeps the SOC seeing — connector/detection health | propose | no untrusted input, no state change |
| **MGR** | Runs the shift — SLA + **regulatory clocks** | propose | no sensitive access, no state change |

## Depth bar (every agent)
1. typed input/output contract + AgBOM · 2. deterministic-first enrichment before any LLM call ·
3. bounded, scoped LLM steps · 4. evidence-cited, schema-validated outputs + calibrated-via-harness
confidence · 5. declared autonomy enforced by the Guardian · 6. ≥1 happy-path + adversarial tests ·
7. documented limits.

## Flow
Triage is read-only: `intake → L1 → (auto_close → resolve | escalate → INTEL + L2 + FUSION) → route`.
Response is explicit and gated: `orchestrator.respond(case, dry_run)` runs **RESP** through the
Guardian (maker-checker for high-impact; crown jewels never auto-isolated). Proactive and service
agents run on-demand/scheduled via `run_agent_on_case(name, …)` and the API.

See the live roster + each AgBOM at `GET /api/agents` or the dashboard's **Agents** tab.
