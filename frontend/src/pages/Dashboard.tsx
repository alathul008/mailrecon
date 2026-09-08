import { useEffect, useMemo, useState } from 'react';
import {
  Search,
  ShieldCheck,
  Database,
  Activity,
  ArrowUpRight,
  LockKeyhole,
} from 'lucide-react';
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

export function Dashboard({ onLookup }: { onLookup: () => void }) {
  const [items, setItems] = useState<DashboardInvestigation[]>([]);

  useEffect(() => {
    listInvestigations().then(setItems).catch(() => {
      // Dashboard remains usable if the API is unavailable.
    });
  }, []);

  const high = items.filter(
    (x) => x.risk_level === 'HIGH' || x.risk_level === 'CRITICAL',
  ).length;

  const avg = items.length
    ? Math.round(
        items.reduce((a, x) => a + (x.risk_score || 0), 0) / items.length,
      )
    : 0;

  const posture = useMemo(
    () => (high ? 'Review required' : 'No high-risk investigations'),
    [high],
  );

  const stats = [
    { label: 'Investigations', value: items.length, icon: Activity },
    { label: 'High-risk', value: high, icon: ShieldCheck },
    { label: 'Average risk', value: avg, icon: Database },
    { label: 'Posture', value: posture, icon: LockKeyhole },
  ];

  return (
    <div className="mx-auto max-w-[1500px] space-y-6 p-5 lg:p-8">
      <div className="flex flex-col justify-between gap-4 md:flex-row md:items-end">
        <div>
          <div className="text-xs uppercase tracking-[.22em] text-red-400">
            Security operations
          </div>
          <h1 className="mt-2 text-3xl font-semibold">
            Investigation dashboard
          </h1>
          <p className="mt-2 text-sm text-zinc-500">
            Local-first email intelligence with evidence provenance and
            explainable risk.
          </p>
        </div>

        <button
          onClick={onLookup}
          className="inline-flex items-center justify-center gap-2 rounded-xl bg-red-500 px-5 py-3 text-sm font-semibold hover:bg-red-400"
        >
          New lookup <Search size={16} />
        </button>
      </div>

      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        {stats.map(({ label, value, icon: Icon }) => (
          <div className="glass rounded-2xl p-5" key={label}>
            <Icon size={18} className="text-red-400" />
            <div className="mt-6 text-xs text-zinc-500">{label}</div>
            <div className="mt-1 text-xl font-semibold">{value}</div>
          </div>
        ))}
      </div>

      <div className="grid gap-4 lg:grid-cols-3">
        <div className="glass rounded-2xl p-6 lg:col-span-2">
          <div className="flex items-center justify-between">
            <div>
              <div className="font-medium">Recent investigations</div>
              <div className="text-xs text-zinc-500">
                Only normalized investigation metadata is shown here.
              </div>
            </div>
            <ArrowUpRight size={17} className="text-zinc-600" />
          </div>

          <div className="mt-5 space-y-2">
            {items.slice(0, 8).map((x) => (
              <div
                className="flex items-center justify-between rounded-xl border border-white/6 p-3"
                key={x.id}
              >
                <div>
                  <div className="text-sm">{x.target}</div>
                  <div className="text-xs text-zinc-600">
                    {new Date(x.created_at).toLocaleString()}
                  </div>
                </div>

                <div className="flex items-center gap-3">
                  <span className="font-mono text-sm">
                    {x.risk_score ?? '—'}
                  </span>
                  <Badge
                    tone={
                      x.risk_level === 'HIGH' || x.risk_level === 'CRITICAL'
                        ? 'danger'
                        : x.risk_level === 'MEDIUM'
                          ? 'warn'
                          : 'good'
                    }
                  >
                    {x.risk_level || x.status}
                  </Badge>
                </div>
              </div>
            ))}

            {items.length === 0 && (
              <div className="py-12 text-center text-sm text-zinc-600">
                No investigations yet. Start with an email lookup.
              </div>
            )}
          </div>
        </div>

        <div className="glass rounded-2xl p-6">
          <div className="font-medium">Operating principles</div>

          <div className="mt-5 space-y-4 text-sm text-zinc-400">
            <div>
              <span className="text-emerald-300">Evidence first.</span>{' '}
              Every finding keeps source, confidence and collection time.
            </div>
            <div>
              <span className="text-emerald-300">No-match is not failure.</span>{' '}
              Provider outages and rate limits remain visible.
            </div>
            <div>
              <span className="text-emerald-300">Local-first.</span> No
              telemetry is required for core investigations.
            </div>
            <div>
              <span className="text-emerald-300">Defensive use.</span> Public
              data and legitimate APIs only.
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
