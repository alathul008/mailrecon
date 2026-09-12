import { getApiKey, API } from './api';

async function request<T>(path: string): Promise<T> {
  const response = await fetch(`${API}${path}`, { headers: getApiKey() ? { Authorization: `Bearer ${getApiKey()}` } : {} });
  if (!response.ok) throw new Error((await response.json().catch(() => ({}))).detail || `Request failed (${response.status})`);
  return response.json() as Promise<T>;
}

export type ExecutionAttemptSummary = {
  execution_id: string;
  execution_attempt_id: string;
  status: string;
  started_at: string;
  finished_at: string | null;
  recovered_at: string | null;
  recovery_reason: string | null;
  current: boolean;
  outcome: string;
};

type Finding = { finding_type: string; source: string; value: string; confidence: number; severity: string; evidence_state: string | null; execution_attempt_id: string | null; source_url: string | null; notes: string | null };
type Change = { key: string[]; before: Finding | null; after: Finding | null };

export type AttemptComparison = {
  investigation_id: number;
  before: ExecutionAttemptSummary;
  after: ExecutionAttemptSummary;
  intelligence: { added: Change[]; removed: Change[]; changed: Change[]; unchanged: Change[]; operationally_inconclusive: Array<{ key: string[]; finding: Finding; provider_status: string[]; reason: string }> };
  operational: { providers: Array<{ provider: string; before: string[]; after: string[] }>; semantics: string };
  risk: { previous_score: number | null; current_score: number | null; score_delta: number | null; previous_risk_level: string | null; current_risk_level: string | null };
  provenance: { current_execution_attempt_id: string | null; historical_findings_remain_attached_to_their_attempt: boolean; identity_confirmation: boolean };
};

export function listAttempts(id: number) { return request<ExecutionAttemptSummary[]>(`/investigations/${id}/attempts`); }
export function getAttempt(id: number, attemptId: string) { return request<unknown>(`/investigations/${id}/attempts/${encodeURIComponent(attemptId)}`); }
export function compareAttempts(id: number, before: string, after: string) { return request<AttemptComparison>(`/investigations/${id}/attempt-comparison?before_attempt_id=${encodeURIComponent(before)}&after_attempt_id=${encodeURIComponent(after)}`); }
