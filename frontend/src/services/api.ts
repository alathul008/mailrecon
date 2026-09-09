import type { Investigation, TimelineEvent } from '../types';

export const API = (
  import.meta.env.VITE_API_URL || 'http://127.0.0.1:8000/api'
).replace(/\/$/, '');

const API_KEY_STORAGE = 'mailrecon_api_key';

export type GraphNode = {
  id: string;
  type: string;
  label: string;
};

export type GraphEdge = {
  source: string;
  target: string;
  relation: string;
};

export type GraphData = {
  nodes: GraphNode[];
  edges: GraphEdge[];
};

// Keep the bearer key for the current browser tab/session only; never persist it
// across browser restarts in localStorage.
export function getApiKey() {
  return window.sessionStorage.getItem(API_KEY_STORAGE) || '';
}

export function setApiKey(key: string) {
  const normalized = key.trim();
  if (normalized) window.sessionStorage.setItem(API_KEY_STORAGE, normalized);
  else window.sessionStorage.removeItem(API_KEY_STORAGE);
}

export function clearApiKey() {
  window.sessionStorage.removeItem(API_KEY_STORAGE);
}

async function request<T>(
  path: string,
  init?: RequestInit,
): Promise<T> {
  const controller = new AbortController();
  const timer = window.setTimeout(() => controller.abort(), 30000);
  const apiKey = getApiKey();

  try {
    const r = await fetch(`${API}${path}`, {
      ...init,
      signal: controller.signal,
      headers: {
        ...(apiKey ? { Authorization: `Bearer ${apiKey}` } : {}),
        ...(init?.body ? { 'content-type': 'application/json' } : {}),
        ...(init?.headers || {}),
      },
    });

    if (!r.ok) {
      let message = `Request failed (${r.status})`;

      try {
        const body = await r.json();
        message = body.detail || body.message || message;
      } catch {
        // Response body may not contain valid JSON.
      }

      if (r.status === 401) {
        clearApiKey();
        window.dispatchEvent(new CustomEvent('mailrecon:auth-required'));
      }

      throw new Error(message);
    }

    return (await r.json()) as T;
  } catch (e) {
    if (e instanceof DOMException && e.name === 'AbortError') {
      throw new Error(
        'Request timed out. Check that the MailRecon API is running.',
      );
    }

    throw e;
  } finally {
    window.clearTimeout(timer);
  }
}

export async function downloadReport(id: number, format: string) {
  const apiKey = getApiKey();
  const response = await fetch(reportUrl(id, format), {
    headers: apiKey ? { Authorization: `Bearer ${apiKey}` } : {},
  });

  if (!response.ok) {
    if (response.status === 401) {
      clearApiKey();
      window.dispatchEvent(new CustomEvent('mailrecon:auth-required'));
    }
    let message = `Request failed (${response.status})`;
    try {
      const body = await response.json();
      message = body.detail || body.message || message;
    } catch {
      // Response body may not contain valid JSON.
    }
    throw new Error(message);
  }

  const blob = await response.blob();
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = `mailrecon-${id}.${format}`;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}

export function createInvestigation(
  email: string,
  privacy_mode = false,
  external_provider_disclosure = true,
) {
  return request<{ id: number; status: string }>('/investigations', {
    method: 'POST',
    body: JSON.stringify({ email, privacy_mode, external_provider_disclosure }),
  });
}

export function getInvestigation(id: number) {
  return request<Investigation>(`/investigations/${id}`);
}

export function listInvestigations() {
  return request<
    Array<{
      id: number;
      target: string;
      status: string;
      risk_score: number | null;
      risk_level: string | null;
      created_at: string;
    }>
  >('/investigations');
}

export function getGraph(id: number) {
  return request<GraphData>(`/investigations/${id}/graph`);
}

export function getTimeline(id: number) {
  return request<TimelineEvent[]>(`/investigations/${id}/timeline`);
}

export function reportUrl(id: number, format: string) {
  return `${API}/investigations/${id}/report?format=${encodeURIComponent(format)}`;
}
