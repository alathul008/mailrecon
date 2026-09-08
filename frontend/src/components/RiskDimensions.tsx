import { ShieldAlert, Fingerprint, Server, Users } from 'lucide-react';

type Props = { dimensions: Record<string, number> };
const labels: Record<string, {label:string; icon:any}> = {
  identity_exposure: {label:'Identity exposure', icon:Fingerprint},
  breach_exposure: {label:'Breach exposure', icon:ShieldAlert},
  domain_security: {label:'Domain security', icon:Server},
  public_footprint: {label:'Public footprint', icon:Users},
};
export function RiskDimensions({dimensions}: Props){
  return <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
    {Object.entries(labels).map(([key,meta])=>{const value=Math.max(0,Math.min(100,Number(dimensions[key]||0))); const I=meta.icon; return <div key={key} className="rounded-xl border border-white/7 bg-white/[.025] p-4">
      <div className="flex items-center justify-between"><div className="flex items-center gap-2 text-xs text-zinc-400"><I size={14}/>{meta.label}</div><span className="font-mono text-xs text-zinc-300">{value}</span></div>
      <div className="mt-3 h-1.5 overflow-hidden rounded-full bg-white/10"><div className="h-full rounded-full bg-red-400" style={{width:`${value}%`}}/></div>
    </div>})}
  </div>
}
