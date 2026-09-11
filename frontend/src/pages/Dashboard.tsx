import { useCallback, useEffect, useMemo, useState } from 'react';
import { Search, ShieldCheck, Database, Activity, ArrowUpRight, LockKeyhole, RefreshCw } from 'lucide-react';
import { listInvestigations } from '../services/api';
import { Badge } from '../components/Badge';

type DashboardInvestigation = {
  id: number;
  target: string;
  status: string;
  risk_score: number | null;
  risk_level: string | null;
  created_at: string;
};

export function Dashboard({ onLookup, onOpen }: { onLookup: () => void; onOpen: (id: number) => void }) {
  const [items, setItems] = useState<DashboardInvestigation[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  const load = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      setItems(await listInvestigations());
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Unable to load recent investigations');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { void load(); }, [load]);

  const high = items.filter((x) => x.risk_level === 'HIGH' || x.risk_level === 'CRITICAL').length;
  const avg = items.length ? Math.round(items.reduce((a, x) => a + (x.risk_score || 0), 0) / items.length) : 0;
  const posture = useMemo(() => high ? 'Review required' : 'No high-risk investigations', [high]);
  const stats = [
    { label: 'Investigations', value: items.length, icon: Activity },
    { label: 'High-risk', value: high, icon: ShieldCheck },
    { label: 'Average risk', value: avg, icon: Database },
    { label: 'Posture', value: posture, icon: LockKeyhole },
  ];

  return <div className="mx-auto max-w-[1500px] space-y-6 p-5 lg:p-8">
    <div className="flex flex-col justify-between gap-4 md:flex-row md:items-end"><div><div className="text-xs uppercase tracking-[.22em] text-red-400">Security operations</div><h1 className="mt-2 text-3xl font-semibold">Investigation dashboard</h1><p className="mt-2 text-sm text-zinc-500">Local-first email intelligence with evidence provenance and explainable risk.</p></div><button onClick={onLookup} className="inline-flex items-center justify-center gap-2 rounded-xl bg-red-500 px-5 py-3 text-sm font-semibold hover:bg-red-400">New lookup <Search size={16}/></button></div>
    <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">{stats.map(({ label, value, icon: Icon }) => <div className="glass rounded-2xl p-5" key={label}><Icon size={18} className="text-red-400"/><div className="mt-6 text-xs text-zinc-500">{label}</div><div className="mt-1 text-xl font-semibold">{value}</div></div>)}</div>
    <div className="grid gap-4 lg:grid-cols-3">
      <div className="glass rounded-2xl p-6 lg:col-span-2">
        <div className="flex items-center justify-between"><div><div className="font-medium">Recent investigations</div><div className="text-xs text-zinc-500">Open an investigation to inspect evidence, providers, timeline, graph, and reports.</div></div><button aria-label="Refresh recent investigations" onClick={() => void load()} className="rounded-lg border border-white/10 p-2 text-zinc-400 hover:bg-white/[.05] hover:text-white"><RefreshCw size={15}/></button></div>
        {error && <div role="alert" className="mt-4 rounded-xl border border-red-500/20 bg-red-500/10 p-3 text-sm text-red-300"><div>{error}</div><button onClick={() => void load()} className="mt-2 inline-flex items-center gap-1 rounded-lg border border-red-400/20 px-3 py-1.5 text-xs hover:bg-red-500/10">Retry</button></div>}
        <div className="mt-5 space-y-2">
          {loading ? <div className="py-12 text-center text-sm text-zinc-600">Loading recent investigations…</div> : items.slice(0, 8).map((x) => <button key={x.id} onClick={() => onOpen(x.id)} className="flex w-full items-center justify-between rounded-xl border border-white/6 p-3 text-left hover:bg-white/[.03] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-red-400"><div className="min-w-0"><div className="truncate text-sm">{x.target}</div><div className="text-xs text-zinc-600">{new Date(x.created_at).toLocaleString()} · #{x.id}</div></div><div className="flex shrink-0 items-center gap-3 pl-3"><span className="font-mono text-sm">{x.risk_score ?? '—'}</span><Badge tone={x.risk_level === 'HIGH' || x.risk_level === 'CRITICAL' ? 'danger' : x.risk_level === 'MEDIUM' ? 'warn' : 'good'}>{x.risk_level || x.status}</Badge><ArrowUpRight size={15} className="text-zinc-600"/></div></button>)}
          {!loading && !items.length && !error && <div className="py-12 text-center text-sm text-zinc-600">No investigations yet. Start with an email lookup.</div>}
        </div>
      </div>
      <div className="glass rounded-2xl p-6"><div className="font-medium">Operating principles</div><div className="mt-5 space-y-4 text-sm text-zinc-400"><div><span className="text-emerald-300">Evidence first.</span> Every finding keeps source, confidence and collection time.</div><div><span className="text-emerald-300">No-match is not failure.</span> Provider outages and rate limits remain visible.</div><div><span className="text-emerald-300">Local-first.</span> No telemetry is required for core investigations.</div><div><span className="text-emerald-300">Defensive use.</span> Public data and legitimate APIs only.</div></div></div>
    </div>
  </div>;
}
