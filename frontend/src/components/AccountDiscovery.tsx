import type { AccountDiscovery as AccountDiscoveryData } from '../services/api';

type Props = { data: AccountDiscoveryData | null; loading: boolean; error: string };

const tones: Record<string, string> = {
  FOUND: 'text-emerald-300 bg-emerald-500/10 border-emerald-500/20',
  POSSIBLE: 'text-amber-300 bg-amber-500/10 border-amber-500/20',
  'NO PUBLIC EVIDENCE': 'text-zinc-300 bg-zinc-500/10 border-zinc-500/20',
  UNAVAILABLE: 'text-zinc-400 bg-zinc-500/5 border-white/8',
  UNCONFIGURED: 'text-orange-300 bg-orange-500/10 border-orange-500/20',
  'RATE LIMITED': 'text-orange-300 bg-orange-500/10 border-orange-500/20',
  ERROR: 'text-red-300 bg-red-500/10 border-red-500/20',
  DISABLED: 'text-zinc-500 bg-zinc-500/5 border-white/5',
};

export function AccountDiscovery({ data, loading, error }: Props) {
  if (loading && !data) return <div className="glass rounded-2xl p-6 text-sm text-zinc-500">Loading public account discovery…</div>;
  if (error && !data) return <div role="alert" className="rounded-2xl border border-red-500/20 bg-red-500/10 p-5 text-sm text-red-300">{error}</div>;
  if (!data) return null;
  const counts = data.services.reduce<Record<string, number>>((acc, row) => { acc[row.status] = (acc[row.status] || 0) + 1; return acc; }, {});
  return <div className="space-y-5">
    <div className="glass rounded-2xl p-5">
      <div className="flex flex-col gap-3 md:flex-row md:items-end md:justify-between"><div><div className="text-[10px] uppercase tracking-[.18em] text-zinc-600">Public account discovery</div><div className="mt-2 break-all font-medium">{data.normalized_email || data.target}</div><div className="mt-1 text-xs text-zinc-600">Username hypothesis: {data.username || '—'} · Domain: {data.domain || '—'}</div></div><div className="flex flex-wrap gap-2">{Object.entries(counts).map(([status, count]) => <span key={status} className={`rounded-full border px-2.5 py-1 text-[10px] ${tones[status] || tones.UNAVAILABLE}`}>{status}: {count}</span>)}</div></div>
      <div className="mt-4 rounded-xl border border-white/7 bg-white/[.02] p-3 text-xs text-zinc-500">Provider status is operational state. Evidence state and confidence describe public evidence strength. No public evidence is not proof that an account does not exist.</div>
    </div>
    <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
      {data.services.map(row => <article key={row.service} className="glass rounded-2xl p-4">
        <div className="flex items-start justify-between gap-3"><div><div className="font-medium">{row.service}</div><div className="mt-1 text-[10px] uppercase tracking-[.14em] text-zinc-600">{row.category}</div></div><span className={`rounded-full border px-2 py-1 text-[10px] ${tones[row.status] || tones.UNAVAILABLE}`}>{row.status}</span></div>
        <div className="mt-4 text-xs text-zinc-500">{row.supported ? `Provider: ${row.provider_status || 'not executed'}` : 'Not implemented — not checked'}</div>
        {row.identifier && <div className="mt-2 break-all text-sm text-zinc-200">{row.identifier}</div>}
        {row.evidence.length > 0 ? <div className="mt-3 space-y-2">{row.evidence.map((e, i) => <div key={`${e.finding_id}-${i}`} className="rounded-lg border border-white/7 bg-white/[.02] p-3"><div className="flex items-center justify-between gap-2"><span className="text-xs text-zinc-300">{e.evidence_state || 'unverified'}</span>{typeof e.confidence === 'number' && <span className="text-xs text-zinc-500">confidence {e.confidence.toFixed(2)}</span>}</div>{e.notes && <div className="mt-1 text-[11px] leading-5 text-zinc-600">{e.notes}</div>}{e.source_url && <a className="mt-2 block break-all text-[11px] text-red-300 hover:text-red-200" href={e.source_url} target="_blank" rel="noreferrer">Source</a>}</div>)}</div> : <div className="mt-3 text-xs text-zinc-600">{row.status === 'NO PUBLIC EVIDENCE' ? 'Checked successfully; no public evidence returned.' : row.status === 'UNAVAILABLE' && !row.supported ? 'This service is intentionally unsupported until a legitimate discovery method is implemented.' : 'No evidence record.'}</div>}
      </article>)}
    </div>
  </div>;
}
