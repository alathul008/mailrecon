import {Badge} from './Badge';
import type {CorrelationResult} from '../services/api';

function stateTone(state?: string){
  if(state==='observed'||state==='corroborated_match'||state==='source_associated')return 'good' as const;
  if(state==='correlated_inferred'||state==='possible_match')return 'warn' as const;
  return 'neutral' as const;
}

export function CorrelationPanel({data}:{data:CorrelationResult}){
  const relationships=data.relationships||[];
  const conflicts=data.conflicts||[];
  return <div className="glass rounded-2xl p-5" data-testid="correlation-panel">
    <div className="flex flex-col gap-1 sm:flex-row sm:items-start sm:justify-between">
      <div><div className="font-medium">Correlation &amp; pivots</div><div className="text-xs text-zinc-500">Explainable relationships built from persisted observations. Correlation is not identity confirmation.</div></div>
      <Badge tone={conflicts.length?'warn':'good'}>{conflicts.length?`${conflicts.length} conflict${conflicts.length===1?'':'s'}`:'No conflicts'}</Badge>
    </div>
    <div className="mt-4 grid gap-3 sm:grid-cols-2">
      {relationships.map((r,index)=><div key={`${r.relationship}-${r.source}-${r.target}-${index}`} className="rounded-xl border border-white/8 bg-white/[.02] p-4" data-testid="correlation-relationship">
        <div className="flex flex-wrap items-center gap-2"><span className="break-all text-sm font-medium">{r.source}</span><span className="text-xs text-zinc-600">→</span><span className="break-all text-sm">{r.target}</span></div>
        <div className="mt-2 flex flex-wrap items-center gap-2"><Badge tone={stateTone(r.evidence_state)}>{r.evidence_state}</Badge><span className="text-xs text-zinc-500">{r.relationship}</span><span className="text-xs text-zinc-600">confidence {Math.round(r.confidence*100)}%</span></div>
        <p className="mt-3 text-xs leading-5 text-zinc-400">{r.explanation}</p>
        <p className="mt-2 text-xs leading-5 text-zinc-600">{r.limitations}</p>
        <div className="mt-3 text-[11px] text-zinc-600">Supporting finding IDs: {r.supporting_finding_ids.length?r.supporting_finding_ids.join(', '):'none'}</div>
      </div>)}
    </div>
    {!relationships.length&&<div className="mt-4 rounded-xl border border-white/8 bg-white/[.02] p-4 text-xs text-zinc-500">No explainable cross-signal relationships are currently available.</div>}
    {conflicts.length>0&&<div className="mt-4 space-y-3" data-testid="correlation-conflicts"><div className="text-xs font-medium uppercase tracking-wider text-amber-300">Provider conflicts</div>{conflicts.map((c,index)=><div key={`${c.finding_type}-${index}`} className="rounded-xl border border-amber-500/20 bg-amber-500/5 p-4"><div className="text-sm font-medium">{c.finding_type}</div><div className="mt-1 break-all text-xs text-zinc-400">{c.values.join(' · ')}</div><div className="mt-2 text-xs text-zinc-600">Providers: {c.provider_sources.join(', ')} · Findings: {c.finding_ids.join(', ')}</div><div className="mt-2 text-xs text-zinc-500">{c.explanation}</div></div>)}</div>}
  </div>;
}
