import type { AgentInfo, Approval, Case, EvalReport, LedgerEntry } from "./types";

async function j<T>(url: string, opts?: RequestInit): Promise<T> {
  const r = await fetch(url, opts);
  if (!r.ok) throw new Error(`${r.status} ${await r.text()}`);
  return r.json() as Promise<T>;
}

const JSON_HEADERS = { "Content-Type": "application/json" };

export const api = {
  provider: () =>
    j<{ provider: string; model: string; offline: boolean; embedding_model_id: string }>("/api/provider"),
  cases: () => j<Case[]>("/api/cases"),
  case: (id: string) => j<Case>(`/api/cases/${id}`),
  ledger: (id: string) =>
    j<{ verified: boolean; entries: LedgerEntry[] }>(`/api/cases/${id}/ledger`),
  ingest: (alert: unknown, memory_enabled: boolean) =>
    j<{ case: Case }>("/api/ingest", {
      method: "POST",
      headers: JSON_HEADERS,
      body: JSON.stringify({ alert, memory_enabled }),
    }),
  respond: (id: string, dry_run: boolean) =>
    j<Case>(`/api/cases/${id}/respond`, {
      method: "POST",
      headers: JSON_HEADERS,
      body: JSON.stringify({ dry_run }),
    }),
  approvals: (status = "pending") => j<Approval[]>(`/api/approvals?status=${status}`),
  approve: (id: string) =>
    j<{ status: string; detail: string }>(`/api/approvals/${id}/approve`, { method: "POST" }),
  deny: (id: string) =>
    j<{ status: string; detail: string }>(`/api/approvals/${id}/deny`, { method: "POST" }),
  agents: () => j<AgentInfo[]>("/api/agents"),
  evaluate: () => j<EvalReport>("/api/eval"),
  memoryStatus: () => j<{ backend: string; count: number; embedding_model: string }>("/api/memory/status"),
  switchProvider: (provider: string, model?: string) =>
    j<{ provider: string; model: string; offline: boolean }>("/api/provider/switch", {
      method: "POST",
      headers: JSON_HEADERS,
      body: JSON.stringify({ provider, model }),
    }),
};

export function openEventStream(onEvent: (e: { topic: string; payload: Record<string, unknown> }) => void): WebSocket {
  const proto = location.protocol === "https:" ? "wss" : "ws";
  const ws = new WebSocket(`${proto}://${location.host}/api/ws`);
  ws.onmessage = (ev) => {
    try {
      onEvent(JSON.parse(ev.data));
    } catch {
      /* ignore malformed frames */
    }
  };
  return ws;
}
