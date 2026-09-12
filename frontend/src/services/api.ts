import type { Investigation, TimelineEvent } from '../types';

export const API = (
  import.meta.env.VITE_API_URL || 'http://127.0.0.1:8000/api'
).replace(/\/$/, '');

const API_KEY_STORAGE = 'mailrecon_api_key';

export type GraphNode = {
  id: string;
  type: string;
  label: string;
  metadata?: Record<string, unknown> | null;
};
export type GraphEdge = { source: string; target: string; relation: string; confidence: number };
export type GraphData = { semantics?: string; provenance?: { type?: string; execution_id?: string | null; execution_attempt_id?: string | null; attempt_status?: string | null }; nodes: GraphNode[]; edges: GraphEdge[] };
export type CorrelationRelationship = { source: string; target: string; relationship: string; evidence_state: string; confidence: number; supporting_finding_ids: number[]; explanation: string; limitations: string };
export type CorrelationConflict = { finding_type: string; values: string[]; provider_sources: string[]; finding_ids: number[]; explanation: string };
export type CorrelationResult = { target_email: string | null; domain: string | null; relationships: CorrelationRelationship[]; conflicts: CorrelationConflict[]; semantics: Record<string, string> };
export type AccountDiscoveryEvidence = { finding_id: number | null; finding_type: string; evidence_state: string | null; confidence: number | null; source: string | null; source_url: string | null; notes: string | null };
export type AccountDiscoveryService = { category: string; service: string; status: string; supported: boolean; discovery_methods: string[]; identifier: string | null; confidence: number | null; provider_status: string | null; checked_at: string | null; evidence: AccountDiscoveryEvidence[] };
export type AccountDiscovery = { investigation_id: number; target: string; normalized_email: string | null; username: string | null; domain: string | null; provider_execution_status: Array<{ provider: string; status: string; checked_at: string | null; message: string | null }>; semantics: Record<string, string>; services: AccountDiscoveryService[] };

export function getApiKey() { return window.sessionStorage.getItem(API_KEY_STORAGE) || ''; }
export function setApiKey(key: string) { const normalized = key.trim(); if (normalized) window.sessionStorage.setItem(API_KEY_STORAGE, normalized); else window.sessionStorage.removeItem(API_KEY_STORAGE); }
export function clearApiKey() { window.sessionStorage.removeItem(API_KEY_STORAGE); }

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const controller = new AbortController(); const timer = window.setTimeout(() => controller.abort(), 30000); const apiKey = getApiKey();
  try {
    const r = await fetch(`${API}${path}`, { ...init, signal: controller.signal, headers: { ...(apiKey ? { Authorization: `Bearer ${apiKey}` } : {}), ...(init?.body ? { 'content-type': 'application/json' } : {}), ...(init?.headers || {}) } });
    if (!r.ok) { let message = `Request failed (${r.status})`; try { const body = await r.json(); message = body.detail || body.message || message; } catch {} if (r.status === 401) { clearApiKey(); window.dispatchEvent(new CustomEvent('mailrecon:auth-required')); } throw new Error(message); }
    return (await r.json()) as T;
  } catch (e) { if (e instanceof DOMException && e.name === 'AbortError') throw new Error('Request timed out. Check that the MailRecon API is running.'); throw e; }
  finally { window.clearTimeout(timer); }
}

export async function downloadReport(id: number, format: string) { const apiKey = getApiKey(); const response = await fetch(reportUrl(id, format), { headers: apiKey ? { Authorization: `Bearer ${apiKey}` } : {} }); if (!response.ok) { if (response.status === 401) { clearApiKey(); window.dispatchEvent(new CustomEvent('mailrecon:auth-required')); } let message = `Request failed (${response.status})`; try { const body = await response.json(); message = body.detail || body.message || message; } catch {} throw new Error(message); } const blob = await response.blob(); const url = URL.createObjectURL(blob); const link = document.createElement('a'); link.href = url; link.download = `mailrecon-${id}.${format}`; document.body.appendChild(link); link.click(); link.remove(); URL.revokeObjectURL(url); }
export function createInvestigation(email: string, privacy_mode = false, external_provider_disclosure = true) { return request<{ id: number; status: string }>('/investigations', { method: 'POST', body: JSON.stringify({ email, privacy_mode, external_provider_disclosure }) }); }
export function deleteInvestigation(id: number) { return request<{ id: number; status: 'deleted' }>(`/investigations/${id}`, { method: 'DELETE' }); }
export function getInvestigation(id: number) { return request<Investigation>(`/investigations/${id}`); }
export function listInvestigations() { return request<Array<{ id: number; target: string; status: string; risk_score: number | null; risk_level: string | null; created_at: string }>>('/investigations'); }
export function getGraph(id: number) { return request<GraphData>(`/investigations/${id}/graph`); }
export function getTimeline(id: number) { return request<TimelineEvent[]>(`/investigations/${id}/timeline`); }
export function getCorrelations(id: number) { return request<CorrelationResult>(`/investigations/${id}/correlations`); }
export function getAccountDiscovery(id: number) { return request<AccountDiscovery>(`/investigations/${id}/account-discovery`); }
export function reportUrl(id: number, format: string) { return `${API}/investigations/${id}/report?format=${encodeURIComponent(format)}`; }
