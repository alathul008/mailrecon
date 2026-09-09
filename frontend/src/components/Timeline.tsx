import { Clock3 } from 'lucide-react';
import type { TimelineEvent } from '../types';
import { Badge } from './Badge';

const evidenceTone=(state?:string|null):'neutral'|'good'|'warn'|'danger'=>{
  if(state==='corroborated_match'||state==='confirmed') return 'good';
  if(state==='possible_match'||state==='source_associated') return 'warn';
  return 'neutral';
};

export function Timeline({events}:{events:TimelineEvent[]}){
  return <section className="glass rounded-2xl p-5">
    <div className="flex items-center gap-2"><Clock3 size={17} className="text-red-400"/><div><div className="font-medium">Investigation timeline</div><div className="text-xs text-zinc-500">Evidence-bearing observations and correlations, newest first.</div></div></div>
    <div className="mt-5 space-y-3">
      {events.length===0 && <div className="py-8 text-center text-sm text-zinc-600">No timeline events available.</div>}
      {events.map((e,i)=><div key={`${e.id}-${i}`} className="flex gap-3 rounded-xl border border-white/7 bg-white/[.02] p-3">
        <div className="mt-1 h-2 w-2 shrink-0 rounded-full bg-red-400"/>
        <div className="min-w-0 flex-1"><div className="flex flex-wrap items-center gap-2"><span className="text-sm font-medium">{e.label}</span><Badge tone={e.severity==='critical'||e.severity==='high'?'danger':e.severity==='medium'?'warn':'neutral'}>{e.kind}</Badge>{e.evidence_state&&<Badge tone={evidenceTone(e.evidence_state)}>{e.evidence_state}</Badge>}</div><div className="mt-1 break-words text-sm text-zinc-400">{e.value}</div><div className="mt-1 text-[11px] text-zinc-600">{e.source} · {Math.round(e.confidence*100)}% confidence · observed {new Date(e.timestamp).toLocaleString()}{e.last_seen&&e.last_seen!==e.timestamp?` · last seen ${new Date(e.last_seen).toLocaleString()}`:''} · collected {new Date(e.collected_at).toLocaleString()}</div></div>
      </div>)}
    </div>
  </section>
}
