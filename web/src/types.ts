export interface Verdict {
  verdict_class: string;
  routing: string;
  confidence: number;
  rationale: string;
  produced_by: string;
  model_id?: string | null;
  attack_techniques: string[];
}

export interface Evidence {
  id: string;
  source: string;
  summary: string;
  supports?: string | null;
}

export interface Entity {
  type: string;
  value: string;
  asset_id?: string | null;
  resolution_confidence: number;
}

export interface CostAccounting {
  tokens_in: number;
  tokens_out: number;
  usd: number;
  model_calls: number;
}

export interface Case {
  id: string;
  tenant_id: string;
  title: string;
  state: string;
  severity: string;
  verdict?: Verdict | null;
  evidence: Evidence[];
  entities: Entity[];
  attack_techniques: string[];
  memory_enabled: boolean;
  cost: CostAccounting;
  updated_at: string;
}

export interface LedgerEntry {
  seq: number;
  action: string;
  actor: string;
  ts: string;
}

export interface Approval {
  id: string;
  case_id?: string | null;
  action: { verb: string; target: string; args?: Record<string, unknown> };
  proposer?: string | null;
  reason: string;
  required_approvals: number;
  approvals_received: number;
  approvers: string[];
  status: string;
  created_at: string;
}

export interface AgentInfo {
  name: string;
  autonomy_level: string;
  agbom: { tools: string[]; data_scopes: string[]; permissions: string[] };
  rule_of_two: { untrusted_input: boolean; sensitive_access: boolean; external_state_change: boolean };
}

export interface EvalReport {
  n: number;
  provider: string;
  precision: number;
  recall: number;
  f1: number;
  false_negative_rate: number;
  verdict_accuracy: number;
  brier_score: number;
  expected_calibration_error: number;
  avg_cost_usd: number;
  missed_ids: string[];
  illustrative_only: boolean;
}
