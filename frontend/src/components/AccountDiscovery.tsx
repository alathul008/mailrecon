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
  if (loading && !data) return <div className="glass rounded-2xl p-6 text-sm text-zinc-500">Searching public account sources…</div>;
  if (error && !data) return <div role="alert" className="rounded-2xl border border-red-500/20 bg-red-500/10 p-5 text-sm text-red-300">{error}</div>;
  if (!data) return null;

  const discovered = data.services.filter(row => row.status === 'FOUND' || row.status === 'POSSIBLE');
  const coverage = data.services.filter(row => row.status !== 'FOUND' && row.status !== 'POSSIBLE');
  const summary = data.summary;

  return <div className="space-y-5">
    <div className="glass rounded-2xl p-5">
      <div className="flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between">
        <div><div className="text-[10px] uppercase tracking-[.18em] text-red-400">Email account intelligence</div><div className="mt-2 break-all text-lg font-semibold">{data.normalized_email || data.target}</div><div className="mt-1 text-xs text-zinc-600">Derived username: {data.username || '—'} · Domain: {data.domain || '—'}</div></div>
        <div className="grid grid-cols-2 gap-2 sm:grid-cols-3 xl:grid-cols-5">
          {[
            ['Accounts found', summary.accounts_found],
            ['Possible', summary.possible_accounts],
            ['Public profiles', summary.public_profiles_observed],
            ['Email-linked', summary.emailrep_profiles],
            ['Breaches', summary.breaches_found],
          ].map(([label, value]) => <div key={label} className="rounded-xl border border-white/7 bg-white/[.025] px-4 py-3"><div className="text-xl font-semibold">{value}</div><div className="text-[10px] uppercase tracking-[.12em] text-zinc-600">{label}</div></div>)}
        </div>
      </div>
      {summary.exposure_signals.length > 0 && <div className="mt-4 flex flex-wrap gap-2">{summary.exposure_signals.map(signal => <span key={signal} className="rounded-full border border-red-500/20 bg-red-500/10 px-2.5 py-1 text-[10px] text-red-300">{signal.replaceAll('_', ' ')}</span>)}</div>}
      <div className="mt-4 rounded-xl border border-white/7 bg-white/[.02] p-3 text-xs text-zinc-500">FOUND means a source directly associated the email with a public profile. POSSIBLE means a public profile exists for a username derived from the email; that correlation is not identity confirmation.</div>
    </div>

    <section className="glass rounded-2xl p-5">
      <div className="flex items-end justify-between gap-3"><div><div className="text-[10px] uppercase tracking-[.18em] text-zinc-600">Discovered accounts</div><h2 className="mt-1 text-xl font-semibold">Online footprint</h2></div><div className="text-xs text-zinc-600">{discovered.length} evidence-backed result{discovered.length === 1 ? '' : 's'}</div></div>
      {discovered.length === 0 ? <div className="mt-5 rounded-xl border border-white/7 bg-white/[.02] p-5 text-sm text-zinc-500">No public account/profile association was observed from the configured sources.</div> : <div className="mt-5 grid gap-3 md:grid-cols-2 xl:grid-cols-3">
        {discovered.map(row => <article key={`${row.provider}-${row.service}`} className="rounded-2xl border border-white/8 bg-white/[.02] p-4">
          <div className="flex items-start justify-between gap-3"><div><div className="font-medium">{row.service}</div><div className="mt-1 text-[10px] uppercase tracking-[.14em] text-zinc-600">{row.category}</div></div><span className={`rounded-full border px-2 py-1 text-[10px] ${tones[row.status] || tones.UNAVAILABLE}`}>{row.status}</span></div>
          {row.identifier && <div className="mt-4 break-all text-sm text-zinc-200">{row.identifier}</div>}
          {row.evidence.map((e, i) => <div key={`${e.finding_id}-${i}`} className="mt-3 rounded-xl border border-white/7 bg-black/10 p-3"><div className="flex items-center justify-between gap-2"><span className="text-xs text-zinc-300">{e.evidence_state || 'unverified'}</span>{typeof e.confidence === 'number' && <span className="text-xs text-zinc-500">{Math.round(e.confidence * 100)}%</span>}</div>{e.notes && <div className="mt-2 text-[11px] leading-5 text-zinc-600">{e.notes}</div>}{e.source_url && <a className="mt-2 block break-all text-[11px] text-red-300 hover:text-red-200" href={e.source_url} target="_blank" rel="noreferrer">Open public profile</a>}</div>)}
        </article>)}
      </div>}
    </section>

    <section className="glass rounded-2xl p-5">
      <div className="flex items-end justify-between gap-3"><div><div className="text-[10px] uppercase tracking-[.18em] text-zinc-600">Coverage</div><h2 className="mt-1 text-lg font-semibold">Services and provider state</h2></div><div className="text-xs text-zinc-600">{summary.services_checked} catalog entries</div></div>
      <div className="mt-4 grid gap-2 sm:grid-cols-2 lg:grid-cols-3">{coverage.map(row => <div key={`${row.provider}-${row.service}`} className="rounded-xl border border-white/7 bg-white/[.02] p-3"><div className="flex items-center justify-between gap-2"><span className="text-sm">{row.service}</span><span className={`rounded-full border px-2 py-1 text-[10px] ${tones[row.status] || tones.UNAVAILABLE}`}>{row.status}</span></div><div className="mt-1 text-[10px] text-zinc-600">{row.supported ? `Provider: ${row.provider_status || 'not executed'}` : 'Not checked'}</div></div>)}</div>
    </section>
  </div>;
}
