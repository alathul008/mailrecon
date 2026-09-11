import { AlertTriangle, CircleHelp, Network, ShieldCheck } from 'lucide-react';
import type { GraphData } from '../services/api';
import type { Finding, Investigation } from '../types';

type BriefingFinding = Finding & { evidence_state?: string | null };

const severityRank: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

export function selectNotableFindings(findings: Finding[], limit = 5): Finding[] {
  return findings
    .filter((finding) => finding.finding_type !== 'risk_dimension' && finding.finding_type !== 'provider_status')
    .slice()
    .sort((a, b) => (severityRank[b.severity?.toLowerCase()] ?? -1) - (severityRank[a.severity?.toLowerCase()] ?? -1) || b.confidence - a.confidence || a.id - b.id)
    .slice(0, limit);
}

function stateLabel(finding: BriefingFinding) {
  return finding.evidence_state || (finding.notes?.match(/Evidence state:\s*([^.]+)/i)?.[1]?.trim() ?? 'unspecified');
}

function confidenceLabel(value: number) {
  return `${Math.round(value * 100)}% confidence`;
}

export function AnalystBriefing({ investigation, findings, graph }: { investigation: Investigation; findings: Finding[]; graph?: GraphData }) {
  const notable = selectNotableFindings(findings);
  const observed = notable.filter((finding) => ['observed', 'confirmed'].includes(stateLabel(finding).toLowerCase()));
  const derived = notable.filter((finding) => !['observed', 'confirmed'].includes(stateLabel(finding).toLowerCase()));
  const sourceCount = new Set(findings.map((finding) => finding.source).filter(Boolean)).size;
  const currentAttemptCount = findings.filter((finding) => finding.current_attempt).length;
  const failedModules = investigation.modules.filter((module) => module.status === 'failed').length;
  const relationships = (graph?.edges || []).slice().sort((a, b) => b.confidence - a.confidence || `${a.source}|${a.target}|${a.relation}`.localeCompare(`${b.source}|${b.target}|${b.relation}`)).slice(0, 3);

  return (
    <section aria-label="Analyst briefing" className="glass rounded-2xl p-5">
      <div className="flex flex-col gap-3 md:flex-row md:items-start md:justify-between">
        <div>
          <div className="flex items-center gap-2"><ShieldCheck size={17} className="text-red-400" /><h2 className="font-medium">Analyst briefing</h2></div>
          <p className="mt-1 max-w-3xl text-xs leading-5 text-zinc-500">A concise reading of the persisted investigation. Observations, derived relationships, and risk interpretation are intentionally kept separate.</p>
        </div>
        <div className="rounded-lg border border-white/8 px-3 py-2 text-right"><div className="text-[10px] uppercase tracking-[.16em] text-zinc-600">Risk interpretation</div><div className="mt-1 font-semibold">{investigation.risk_score == null ? 'Unavailable' : `${investigation.risk_score}/100 · ${investigation.risk_level || 'Unrated'}`}</div></div>
      </div>

      <div className="mt-5 grid gap-4 lg:grid-cols-3">
        <div className="rounded-xl border border-white/8 bg-white/[.02] p-4">
          <div className="flex items-center gap-2 text-xs font-medium"><AlertTriangle size={14} className="text-zinc-400" />Observed evidence</div>
          <div className="mt-1 text-[11px] text-zinc-600">Persisted findings; not identity confirmation.</div>
          <div className="mt-3 space-y-2">
            {observed.length ? observed.map((finding) => <div key={finding.id} className="rounded-lg border border-white/7 p-3"><div className="flex justify-between gap-2 text-xs"><span className="font-medium">#{finding.id} · {finding.finding_type}</span><span className="text-zinc-500">{finding.severity}</span></div><div className="mt-1 break-words text-xs text-zinc-300">{finding.value}</div><div className="mt-2 text-[10px] text-zinc-600">{finding.source} · {confidenceLabel(finding.confidence)}</div></div>) : <div className="text-xs text-zinc-600">No findings explicitly marked observed/confirmed.</div>}
          </div>
        </div>

        <div className="rounded-xl border border-white/8 bg-white/[.02] p-4">
          <div className="flex items-center gap-2 text-xs font-medium"><Network size={14} className="text-zinc-400" />Derived assessment</div>
          <div className="mt-1 text-[11px] text-zinc-600">Current graph view and analyst-oriented evidence grouping.</div>
          <div className="mt-3 space-y-2 text-xs">
            <div className="flex justify-between rounded-lg border border-white/7 p-3"><span>Graph entities</span><span className="font-medium">{graph?.nodes.length ?? '—'}</span></div>
            <div className="flex justify-between rounded-lg border border-white/7 p-3"><span>Graph relationships</span><span className="font-medium">{graph?.edges.length ?? '—'}</span></div>
            {relationships.map((edge) => <div key={`${edge.source}|${edge.target}|${edge.relation}`} className="rounded-lg border border-white/7 p-3"><div className="break-words text-zinc-300">{edge.source} → {edge.target}</div><div className="mt-1 text-[10px] text-zinc-600">{edge.relation} · {confidenceLabel(edge.confidence)} · derived relationship</div></div>)}
            {derived.length > 0 && <div className="rounded-lg border border-dashed border-white/8 p-3 text-zinc-500">{derived.length} notable finding{derived.length === 1 ? '' : 's'} require contextual review because their evidence state is not explicitly observed.</div>}
          </div>
        </div>

        <div className="rounded-xl border border-white/8 bg-white/[.02] p-4">
          <div className="flex items-center gap-2 text-xs font-medium"><CircleHelp size={14} className="text-zinc-400" />Provenance & execution</div>
          <div className="mt-3 grid gap-2 text-xs">
            <div className="rounded-lg border border-white/7 p-3"><div className="text-zinc-600">Evidence sources</div><div className="mt-1 font-medium">{sourceCount}</div></div>
            <div className="rounded-lg border border-white/7 p-3"><div className="text-zinc-600">Findings from current attempt</div><div className="mt-1 font-medium">{currentAttemptCount}</div></div>
            <div className="rounded-lg border border-white/7 p-3"><div className="text-zinc-600">Execution modules</div><div className="mt-1 font-medium">{investigation.modules.length} · {failedModules ? `${failedModules} failed` : 'no failures recorded'}</div></div>
            <div className="rounded-lg border border-white/7 p-3"><div className="text-zinc-600">Investigation status</div><div className="mt-1 font-medium capitalize">{investigation.status}</div></div>
          </div>
          <div className="mt-3 rounded-lg border border-dashed border-white/8 p-3 text-[11px] leading-4 text-zinc-600">Use the Evidence, Providers, Timeline, and Graph tabs to inspect the exact source, evidence state, collection context, and producing execution attempt before drawing conclusions.</div>
        </div>
      </div>

      <div className="mt-4 rounded-xl border border-red-500/15 bg-red-500/5 p-3 text-[11px] leading-4 text-zinc-500">Risk score and risk level are interpretations produced by the existing risk engine. They do not establish identity. Possible matches and graph correlations remain probabilistic and should be independently verified.</div>
    </section>
  );
}
