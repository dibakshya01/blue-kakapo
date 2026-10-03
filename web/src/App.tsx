import { useCallback, useEffect, useState } from "react";
import { api, openEventStream } from "./api";
import type { AgentInfo, Case, EvalReport, LedgerEntry } from "./types";

const SAMPLES: Record<string, unknown> = {
  malicious: { title: "Outbound connection to known C2", severity: "high", rule_name: "C2 beacon detected", src_ip: "10.0.0.14", dst_ip: "198.51.100.23", host: "WS-14", user: "svc-web", domain: "malware.example", attack_techniques: ["T1071"], message: "Host contacted malware.example over HTTPS" },
  benign: { title: "Scheduled backup login (test)", severity: "low", rule_name: "Successful login", src_ip: "10.0.0.9", user: "backup-svc", domain: "internal.example", message: "Routine scheduled backup job authenticated" },
  suspicious: { title: "Encoded PowerShell exploit attempt", severity: "medium", rule_name: "Suspicious PowerShell", host: "WS-204", user: "jdoe", message: "Possible credential access via encoded PowerShell" },
};

const badgeClass = (v?: string) =>
  ({ benign: "b-green", false_positive: "b-green", suspicious: "b-amber", inconclusive: "b-amber", malicious: "b-red" } as Record<string, string>)[v ?? ""] ?? "b-muted";
const routeClass = (r?: string) =>
  ({ auto_close: "b-green", escalate: "b-amber", await_approval: "b-blue" } as Record<string, string>)[r ?? ""] ?? "b-blue";

function Badge({ text, cls }: { text: string; cls: string }) {
  return <span className={`badge ${cls}`}>{text}</span>;
}

export function App() {
  const [tab, setTab] = useState<"cases" | "agents" | "settings">("cases");
  const [provider, setProvider] = useState<{ provider: string; offline: boolean } | null>(null);
  const [connected, setConnected] = useState(false);
  const [cases, setCases] = useState<Case[]>([]);
  const [selected, setSelected] = useState<string | null>(null);

  const refreshCases = useCallback(async () => {
    try {
      setCases(await api.cases());
    } catch { /* ignore */ }
  }, []);

  useEffect(() => {
    api.provider().then(setProvider).catch(() => setProvider(null));
    refreshCases();
    const ws = openEventStream(() => refreshCases());
    ws.onopen = () => setConnected(true);
    ws.onclose = () => setConnected(false);
    return () => ws.close();
  }, [refreshCases]);

  return (
    <div className="app">
      <div className="topbar">
        <span className={`dot ${connected ? "" : "off"}`} />
        <h1>🦜 blue-kakapo</h1>
        <span className="tag">{provider ? `provider: ${provider.provider}${provider.offline ? " (offline)" : ""}` : "…"}</span>
        <span className="tag">Tier-1 triage · coworker</span>
        <div className="nav">
          {(["cases", "agents", "settings"] as const).map((t) => (
            <button key={t} className={tab === t ? "active" : ""} onClick={() => setTab(t)}>
              {t[0].toUpperCase() + t.slice(1)}
            </button>
          ))}
        </div>
      </div>
      <div className="body">
        {tab === "cases" && (
          <CasesView cases={cases} selected={selected} onSelect={setSelected} onChanged={refreshCases} />
        )}
        {tab === "agents" && <AgentsView />}
        {tab === "settings" && <SettingsView onProvider={setProvider} />}
      </div>
    </div>
  );
}

function CasesView({ cases, selected, onSelect, onChanged }: {
  cases: Case[]; selected: string | null; onSelect: (id: string) => void; onChanged: () => void;
}) {
  const [alertText, setAlertText] = useState(JSON.stringify(SAMPLES.malicious, null, 2));
  const [mem, setMem] = useState(false);
  const [busy, setBusy] = useState(false);

  const triage = async () => {
    let alert: unknown;
    try { alert = JSON.parse(alertText); } catch { alert = { title: "Free-text alert", message: alertText }; }
    setBusy(true);
    try {
      const res = await api.ingest(alert, mem);
      await onChanged();
      onSelect(res.case.id);
    } finally { setBusy(false); }
  };

  return (
    <>
      <div className="col left">
        <div className="card">
          <h2>Triage an alert</h2>
          <textarea value={alertText} onChange={(e) => setAlertText(e.target.value)} spellCheck={false} />
          <div className="row mt">
            <button className="btn" onClick={triage} disabled={busy}>{busy ? "Triaging…" : "Triage"}</button>
            {Object.keys(SAMPLES).map((k) => (
              <button key={k} className="btn ghost" onClick={() => setAlertText(JSON.stringify(SAMPLES[k], null, 2))}>{k}</button>
            ))}
            <label className="row" style={{ gap: 4, marginLeft: "auto", color: "var(--muted)", fontSize: 12 }}>
              <input type="checkbox" checked={mem} onChange={(e) => setMem(e.target.checked)} /> use memory
            </label>
          </div>
        </div>
        <div className="card">
          <h2>Cases ({cases.length})</h2>
          <div className="caselist">
            {cases.length === 0 && <div className="empty">No cases yet — triage an alert above.</div>}
            {cases.map((c) => (
              <div key={c.id} className={`caseitem ${selected === c.id ? "sel" : ""}`} onClick={() => onSelect(c.id)}>
                <div><div className="t">{c.title}</div><div className="m">{c.severity} · {c.state}</div></div>
                <Badge text={c.verdict?.verdict_class ?? "—"} cls={badgeClass(c.verdict?.verdict_class)} />
              </div>
            ))}
          </div>
        </div>
      </div>
      <div className="col right">
        {selected ? <CaseDetail id={selected} onChanged={onChanged} /> : (
          <div className="card"><h2>Case detail</h2><div className="empty">Select or triage a case to see its verdict, evidence, reasoning trace, and run a gated response.</div></div>
        )}
      </div>
    </>
  );
}

function CaseDetail({ id, onChanged }: { id: string; onChanged: () => void }) {
  const [c, setC] = useState<Case | null>(null);
  const [trace, setTrace] = useState<{ verified: boolean; entries: LedgerEntry[] } | null>(null);
  const [responding, setResponding] = useState(false);

  const load = useCallback(async () => {
    setC(await api.case(id));
    setTrace(await api.ledger(id));
  }, [id]);
  useEffect(() => { load(); }, [load]);

  if (!c) return <div className="card"><h2>Case detail</h2><div className="empty">Loading…</div></div>;
  const v = c.verdict;

  const runRespond = async () => {
    setResponding(true);
    try { await api.respond(id, true); await load(); await onChanged(); } finally { setResponding(false); }
  };

  return (
    <>
      <div className="card">
        <div className="row spread">
          <h2>Case detail</h2>
          <span className="m muted" style={{ fontFamily: "var(--mono)", fontSize: 11 }}>{c.id}</span>
        </div>
        <div className="verdict">
          {v?.verdict_class ?? "—"}{" "}
          {v && <Badge text={v.routing} cls={routeClass(v.routing)} />}
        </div>
        <div className="conf">
          confidence {v ? `${Math.round(v.confidence * 100)}%` : "—"} · by {v?.produced_by ?? "L1"} · model {v?.model_id ?? "—"} · state {c.state}
        </div>
        {v?.rationale && <p>{v.rationale}</p>}
        <div className="row">
          {c.attack_techniques.map((t) => <Badge key={t} text={t} cls="b-blue" />)}
          {c.cost.usd > 0 && <span className="tag">cost ${c.cost.usd.toFixed(4)}</span>}
        </div>
        <div className="row mt">
          <button className="btn warn" onClick={runRespond} disabled={responding}>
            {responding ? "Running…" : "Run response (dry-run)"}
          </button>
          <span className="muted" style={{ fontSize: 12 }}>Containment is Guardian-gated & human-approved.</span>
        </div>
      </div>

      <div className="card">
        <h2>Evidence ({c.evidence.length})</h2>
        {c.evidence.length === 0 && <div className="empty">No evidence.</div>}
        {c.evidence.map((e) => (
          <div className="ev" key={e.id}>
            <span className="src">{e.source}</span>{e.summary} {e.supports && <span className="sup">[{e.supports}]</span>}
          </div>
        ))}
      </div>

      <div className="card">
        <h2>Reasoning trace {trace && <span className={trace.verified ? "b-green badge" : "b-red badge"}>{trace.verified ? "ledger verified ✓" : "⚠ unverified"}</span>}</h2>
        <div className="trace">
          {trace?.entries.map((e) => <div key={e.seq}>#{e.seq} · {e.actor} · {e.action}</div>)}
        </div>
      </div>
    </>
  );
}

function AgentsView() {
  const [agents, setAgents] = useState<AgentInfo[]>([]);
  useEffect(() => { api.agents().then(setAgents).catch(() => setAgents([])); }, []);
  return (
    <div className="full">
      <h2>Agent roster — the swarm (core-5)</h2>
      <div className="grid">
        {agents.map((a) => (
          <div className="card" key={a.name}>
            <div className="row spread">
              <strong>{a.name}</strong>
              <Badge text={a.autonomy_level} cls={a.autonomy_level === "act_on_approval" ? "b-amber" : "b-blue"} />
            </div>
            <div className="kv"><span className="k">tools</span><span>{a.agbom.tools.join(", ") || "—"}</span></div>
            <div className="kv"><span className="k">data scopes</span><span>{a.agbom.data_scopes.join(", ") || "—"}</span></div>
            <div className="kv"><span className="k">rule of two</span>
              <span className="row" style={{ gap: 4 }}>
                <span className={`leg ${a.rule_of_two.untrusted_input ? "on" : ""}`}>untrusted-in</span>
                <span className={`leg ${a.rule_of_two.sensitive_access ? "on" : ""}`}>sensitive</span>
                <span className={`leg ${a.rule_of_two.external_state_change ? "on" : ""}`}>state-change</span>
              </span>
            </div>
            <div className="muted" style={{ fontSize: 11, marginTop: 6 }}>
              {[a.rule_of_two.untrusted_input, a.rule_of_two.sensitive_access, a.rule_of_two.external_state_change].filter(Boolean).length < 3 ? "✓ breaks a leg" : "⚠ all three legs"}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

function SettingsView({ onProvider }: { onProvider: (p: { provider: string; offline: boolean }) => void }) {
  const [provider, setProvider] = useState("offline");
  const [model, setModel] = useState("");
  const [mem, setMem] = useState<{ backend: string; count: number; embedding_model: string } | null>(null);
  const [report, setReport] = useState<EvalReport | null>(null);
  const [evaluating, setEvaluating] = useState(false);

  useEffect(() => { api.memoryStatus().then(setMem).catch(() => setMem(null)); }, []);

  const doSwitch = async () => {
    const r = await api.switchProvider(provider, model || undefined);
    onProvider({ provider: r.provider, offline: r.offline });
  };
  const doEval = async () => {
    setEvaluating(true);
    try { setReport(await api.evaluate()); } finally { setEvaluating(false); }
  };

  return (
    <div className="full">
      <div className="card">
        <h2>LLM provider</h2>
        <div className="row">
          <select value={provider} onChange={(e) => setProvider(e.target.value)}>
            <option value="offline">offline (deterministic, no key)</option>
            <option value="anthropic">anthropic</option>
            <option value="openai">openai-compatible (incl. Azure/vLLM/LM Studio)</option>
            <option value="ollama">ollama (local)</option>
          </select>
          <input type="text" placeholder="model (optional)" value={model} onChange={(e) => setModel(e.target.value)} />
          <button className="btn" onClick={doSwitch}>Switch</button>
        </div>
        <div className="muted mt" style={{ fontSize: 12 }}>Switchable anytime. Keys are set via BK_ env vars, never entered here.</div>
      </div>

      <div className="card">
        <h2>Case memory</h2>
        {mem ? (
          <div className="kv"><span className="k">backend</span><span>{mem.backend} · {mem.count} record(s) · {mem.embedding_model}</span></div>
        ) : <div className="empty">unavailable</div>}
        <div className="muted" style={{ fontSize: 12 }}>Opt-in per case. Local mode links a folder; agent-authored memories are quarantined until reviewed.</div>
      </div>

      <div className="card">
        <h2>Evaluation harness</h2>
        <button className="btn" onClick={doEval} disabled={evaluating}>{evaluating ? "Running…" : "Run eval (bundled dataset)"}</button>
        {report && (
          <pre className="report">{`provider           : ${report.provider}
threat precision   : ${report.precision}
threat recall      : ${report.recall}
FALSE-NEGATIVE RATE: ${report.false_negative_rate}  (missed: ${report.missed_ids.join(", ") || "none"})
verdict accuracy   : ${report.verdict_accuracy}
Brier / ECE        : ${report.brier_score} / ${report.expected_calibration_error}
avg cost / case    : $${report.avg_cost_usd}
${report.illustrative_only ? "NOTE: offline — ILLUSTRATIVE FLOOR, not a real-world claim." : ""}`}</pre>
        )}
      </div>
    </div>
  );
}
