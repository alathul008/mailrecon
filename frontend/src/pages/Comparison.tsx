import { useEffect, useMemo, useState } from 'react';
import { ArrowLeft, GitCompareArrows, LoaderCircle } from 'lucide-react';
import { getInvestigation, listInvestigations } from '../services/api';
import type { Investigation } from '../types';
import { compareFindings, findingCounts, riskDimensionMap } from '../services/comparison';

type Summary = { id: number; target: string; status: string; risk_score: number | null; risk_level: string | null; created_at: string };

function fmt(value: number | null | undefined) { return value == null ? '—' : String(Math.round(value)); }

export function Comparison({ onBack, initialLeft, initialRight }: { onBack: () => void; initialLeft?: number; initialRight?: number }) {
  const [items, setItems] = useState<Summary[]>([]);
  const [leftId, setLeftId] = useState<number | ''>(initialLeft ?? '');
  const [rightId, setRightId] = useState<number | ''>(initialRight ?? '');
  const [left, setLeft] = useState<Investigation | null>(null);
  const [right, setRight] = useState<Investigation | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => { void listInvestigations().then(setItems).catch(e => setError(e instanceof Error ? e.message : 'Unable to load investigations')).finally(() => setLoading(false)); }, []);

  useEffect(() => {
    if (!leftId || !rightId || leftId === rightId) { setLeft(null); setRight(null); return; }
    setError('');
    Promise.all([getInvestigation(leftId), getInvestigation(rightId)]).then(([a, b]) => { setLeft(a); setRight(b); }).catch(e => setError(e instanceof Error ? e.message : 'Unable to load comparison')).finally(() => setLoading(false));
  }, [leftId, rightId]);

  const changes = useMemo(() => left && right ? compareFindings(left.findings, right.findings) : [], [left, right]);
  const counts = useMemo(() => findingCounts(changes), [changes]);
  const leftDimensions = left ? riskDimensionMap(left) : {};
  const rightDimensions = right ? riskDimensionMap(right) : {};
  const dimensions = Array.from(new Set([...Object.keys(leftDimensions), ...Object.keys(rightDimensions)])).sort();

  return <div className="mx-auto max-w-[1500px] space-y-6 p-5 lg:p-8">
    <button onClick={onBack} className="inline-flex items-center gap-2 text-xs text-zinc-500 hover:text-white"><ArrowLeft size={14}/> Back to investigations</button>
    <div><div className="text-xs font-medium uppercase tracking-[.22em] text-red-400">Analyst workspace</div><h1 className="mt-2 text-3xl font-semibold tracking-tight">Compare investigations</h1><p className="mt-2 max-w-3xl text-sm text-zinc-500">Compare persisted evidence snapshots without merging identities. Added, removed, and changed evidence are derived from source, finding type, and value.</p></div>
    <div className="glass grid gap-4 rounded-2xl p-5 md:grid-cols-2">
      <label className="text-sm"><span className="mb-2 block text-xs uppercase tracking-wider text-zinc-500">Earlier / baseline investigation</span><select aria-label="Baseline investigation" value={leftId} onChange={e => setLeftId(e.target.value ? Number(e.target.value) : '')} className="w-full rounded-xl border border-white/10 bg-[#101010] px-3 py-3"><option value="">Select investigation…</option>{items.map(x => <option key={x.id} value={x.id}>#{x.id} — {x.target}</option>)}</select></label>
      <label className="text-sm"><span className="mb-2 block text-xs uppercase tracking-wider text-zinc-500">Later / comparison investigation</span><select aria-label="Comparison investigation" value={rightId} onChange={e => setRightId(e.target.value ? Number(e.target.value) : '')} className="w-full rounded-xl border border-white/10 bg-[#101010] px-3 py-3"><option value="">Select investigation…</option>{items.map(x => <option key={x.id} value={x.id}>#{x.id} — {x.target}</option>)}</select></label>
    </div>
    {error && <div role="alert" className="rounded-xl border border-red-500/20 bg-red-500/10 p-4 text-sm text-red-300">{error}</div>}
    {loading && !left && <div className="glass rounded-2xl p-10 text-center text-sm text-zinc-500"><LoaderCircle className="mx-auto mb-3 animate-spin" size={22}/>Loading comparison…</div>}
    {left && right && <div className="space-y-5">
      <div className="grid gap-4 md:grid-cols-2"><div className="glass rounded-2xl p-5"><div className="text-xs text-zinc-500">Baseline #{left.id}</div><div className="mt-2 break-all font-medium">{left.target}</div><div className="mt-2 text-sm text-zinc-500">Risk: {fmt(left.risk_score)} / 100 · {left.risk_level || 'unknown'}</div></div><div className="glass rounded-2xl p-5"><div className="text-xs text-zinc-500">Comparison #{right.id}</div><div className="mt-2 break-all font-medium">{right.target}</div><div className="mt-2 text-sm text-zinc-500">Risk: {fmt(right.risk_score)} / 100 · {right.risk_level || 'unknown'}</div></div></div>
      <div className="grid gap-3 sm:grid-cols-4">{([['added', counts.added], ['removed', counts.removed], ['changed', counts.changed], ['unchanged', counts.unchanged]] as const).map(([label, value]) => <div key={label} className="glass rounded-2xl p-5"><div className="text-xs uppercase tracking-wider text-zinc-500">{label}</div><div className="mt-2 text-2xl font-semibold">{value}</div></div>)}</div>
      <div className="glass rounded-2xl p-5"><div className="flex items-center gap-2"><GitCompareArrows size={17} className="text-red-400"/><div><div className="font-medium">Risk change</div><div className="text-xs text-zinc-500">Risk values are compared as persisted; no score is recomputed here.</div></div></div><div className="mt-4 grid gap-3 sm:grid-cols-2"><div className="rounded-xl border border-white/7 p-4">Score delta <span className="ml-2 font-semibold">{left.risk_score != null && right.risk_score != null ? `${right.risk_score - left.risk_score > 0 ? '+' : ''}${Math.round(right.risk_score - left.risk_score)}` : '—'}</span></div><div className="rounded-xl border border-white/7 p-4">Level <span className="ml-2 font-semibold">{left.risk_level || 'unknown'} → {right.risk_level || 'unknown'}</span></div></div></div>
      {dimensions.length > 0 && <div className="glass rounded-2xl p-5"><div className="font-medium">Risk dimensions</div><div className="mt-4 overflow-x-auto"><table className="w-full text-left text-sm"><thead className="text-xs uppercase tracking-wider text-zinc-500"><tr><th className="py-3">Dimension</th><th className="py-3">Baseline</th><th className="py-3">Comparison</th><th className="py-3">Delta</th></tr></thead><tbody>{dimensions.map(key => { const a = leftDimensions[key]; const b = rightDimensions[key]; return <tr key={key} className="border-t border-white/6"><td className="py-3">{key}</td><td className="py-3">{fmt(a)}</td><td className="py-3">{fmt(b)}</td><td className="py-3">{a != null && b != null ? `${b-a > 0 ? '+' : ''}${b-a}` : '—'}</td></tr>; })}</tbody></table></div></div>}
      <div className="glass overflow-hidden rounded-2xl"><div className="border-b border-white/8 px-5 py-4 font-medium">Evidence changes</div><div className="overflow-x-auto"><table className="w-full text-left text-sm"><thead className="bg-white/[.025] text-xs uppercase tracking-wider text-zinc-500"><tr><th className="px-5 py-3">Status</th><th className="px-5 py-3">Type</th><th className="px-5 py-3">Source</th><th className="px-5 py-3">Value</th><th className="px-5 py-3">Confidence</th></tr></thead><tbody>{changes.map(c => { const f=c.after || c.before!; return <tr key={c.key} className="border-t border-white/6"><td className="px-5 py-3 capitalize">{c.status}</td><td className="px-5 py-3">{c.findingType}</td><td className="px-5 py-3">{c.source}</td><td className="max-w-xl break-all px-5 py-3">{c.value}</td><td className="px-5 py-3">{c.status==='changed' ? `${Math.round((c.before!.confidence)*100)}% → ${Math.round((c.after!.confidence)*100)}%` : `${Math.round(f.confidence*100)}%`}</td></tr>; })}</tbody></table>{changes.length===0&&<div className="p-8 text-center text-sm text-zinc-500">No comparable evidence was found.</div>}</div></div>
    </div>}
    {!loading && (!leftId || !rightId) && <div className="glass rounded-2xl p-12 text-center text-sm text-zinc-500">Select two different investigations to begin comparison.</div>}
    {leftId && rightId && leftId === rightId && <div role="alert" className="rounded-xl border border-amber-500/20 bg-amber-500/10 p-4 text-sm text-amber-300">Choose two different investigations.</div>}
  </div>;
}
