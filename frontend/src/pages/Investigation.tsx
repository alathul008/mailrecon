import {useCallback,useEffect,useState} from 'react';
import {ArrowLeft,Download,LoaderCircle,Network,RefreshCw,Trash2} from 'lucide-react';
import {deleteInvestigation,downloadReport,getGraph,getInvestigation,getTimeline,createInvestigation,type GraphData} from '../services/api';
import type {Finding,Investigation as InvestigationType,TimelineEvent} from '../types';
import {AnalystBriefing} from '../components/AnalystBriefing';
import {Badge} from '../components/Badge';
import {RiskCard} from '../components/RiskCard';
import {RiskDimensions} from '../components/RiskDimensions';
import {EvidenceExplorer} from '../components/EvidenceExplorer';
import {ExecutionStatus} from '../components/ExecutionStatus';
import {ProviderStatusGrid} from '../components/ProviderStatusGrid';
import {Timeline} from '../components/Timeline';
import {Graph} from './Graph';
import {getPivotTarget} from '../services/workspace';

const tabs=['Overview','Evidence','Providers','Timeline','Graph','Reports'] as const;
type Tab=typeof tabs[number];

export function Investigation({id,onBack,onOpen}:{id:number;onBack:()=>void;onOpen:(id:number)=>void}){
 const [inv,setInv]=useState<InvestigationType|null>(null);const [timeline,setTimeline]=useState<TimelineEvent[]>([]);const [graphData,setGraphData]=useState<GraphData>();const [tab,setTab]=useState<Tab>('Overview');const [loading,setLoading]=useState(true);const [error,setError]=useState('');const [deleting,setDeleting]=useState(false);const [pivoting,setPivoting]=useState(false);const [focusFindingId,setFocusFindingId]=useState<number>();
 const load=useCallback(async()=>{setLoading(true);setError('');try{const data=await getInvestigation(id);setInv(data);setTimeline(await getTimeline(id))}catch(e){setError(e instanceof Error?e.message:'Unable to load investigation')}finally{setLoading(false)}},[id]);
 useEffect(()=>{void load()},[load]);
 useEffect(()=>{let active=true;setGraphData(undefined);getGraph(id).then(data=>{if(active)setGraphData(data)}).catch(()=>{if(active)setGraphData(undefined)});return()=>{active=false}},[id]);
 useEffect(()=>{if(!inv||!['queued','running'].includes(inv.status))return;const timer=window.setInterval(async()=>{try{const data=await getInvestigation(id);setInv(data);if(data.status!=='queued'&&data.status!=='running')setTimeline(await getTimeline(id))}catch(e){setError(e instanceof Error?e.message:'Unable to refresh investigation')}},2000);return()=>window.clearInterval(timer)},[id,inv?.status]);
 useEffect(()=>{const onAuth=()=>setError('Authentication required. Enter your MailRecon API key before continuing.');window.addEventListener('mailrecon:auth-required',onAuth);return()=>window.removeEventListener('mailrecon:auth-required',onAuth)},[]);
 const dimensions=Object.fromEntries((inv?.findings||[]).filter(f=>f.finding_type==='risk_dimension').map(f=>{const [k,v]=f.value.split('=');return [k,Number(v)]}));
 const providers=(inv?.findings||[]).filter(f=>f.finding_type==='provider_status');
 const modules=inv?.modules||[];
 const findingCount=inv?.findings.length||0;
 async function remove(){if(!inv||!window.confirm(`Permanently delete investigation #${inv.id} and all stored investigation data? This cannot be undone.`))return;setDeleting(true);setError('');try{const result=await deleteInvestigation(inv.id);if(result.status!=='deleted')throw new Error('Unexpected deletion response.');onBack()}catch(e){setError(e instanceof Error?e.message:'Deletion failed')}finally{setDeleting(false)}}
 async function pivot(finding:Finding){const target=getPivotTarget(finding);if(!target||pivoting)return;setPivoting(true);setError('');try{const created=await createInvestigation(target,false,true);onOpen(created.id)}catch(e){setError(e instanceof Error?e.message:'Pivot failed')}finally{setPivoting(false)}}
 function openGraphEvidence(findingId:number){if(!(inv?.findings||[]).some(f=>f.id===findingId)){setError('The selected graph evidence is not present in this investigation.');return}setFocusFindingId(findingId);setTab('Evidence')}
 async function report(format:string){try{await downloadReport(id,format)}catch(e){setError(e instanceof Error?e.message:'Report export failed')}}
 if(loading&&!inv)return <div className="mx-auto max-w-[1500px] p-8"><div className="glass rounded-2xl p-12 text-center text-sm text-zinc-500"><LoaderCircle className="mx-auto mb-3 animate-spin" size={22}/>Loading investigation #{id}…</div></div>;
 if(error&&!inv)return <div className="mx-auto max-w-[1500px] space-y-4 p-8"><button onClick={onBack} className="inline-flex items-center gap-2 text-sm text-zinc-400 hover:text-white"><ArrowLeft size={16}/> Back to investigations</button><div role="alert" className="rounded-xl border border-red-500/20 bg-red-500/10 p-4 text-sm text-red-300">{error}</div></div>;
 if(!inv)return null;
 const graphFindings=inv.findings.filter(f=>f.finding_type!=='risk_dimension'&&f.finding_type!=='provider_status');
 return <div className="mx-auto max-w-[1500px] space-y-6 p-5 lg:p-8">
  <div className="flex flex-col gap-4 md:flex-row md:items-start md:justify-between"><div><button onClick={onBack} className="mb-4 inline-flex items-center gap-2 text-xs text-zinc-500 hover:text-white"><ArrowLeft size={14}/> All investigations</button><div className="text-xs uppercase tracking-[.22em] text-red-400">Investigation #{inv.id}</div><h1 className="mt-2 text-2xl font-semibold tracking-tight break-all">{inv.target}</h1><div className="mt-2 flex flex-wrap items-center gap-2"><ExecutionStatus status={inv.status}/><span className="text-xs text-zinc-600">Created {new Date(inv.created_at).toLocaleString()}</span></div></div><div className="flex gap-2"><button onClick={load} className="inline-flex items-center gap-1.5 rounded-lg border border-white/10 px-3 py-2 text-xs hover:bg-white/[.05]"><RefreshCw size={13}/> Refresh</button><button onClick={remove} disabled={deleting} className="inline-flex items-center gap-1.5 rounded-lg border border-red-500/20 px-3 py-2 text-xs text-red-300 hover:bg-red-500/10 disabled:opacity-50"><Trash2 size={13}/>{deleting?'Deleting…':'Delete'}</button></div></div>
  {error&&<div role="alert" className="rounded-xl border border-red-500/20 bg-red-500/10 p-4 text-sm text-red-300">{error}</div>}
  <div className="flex gap-1 overflow-x-auto border-b border-white/8">{tabs.map(item=><button key={item} onClick={()=>setTab(item)} className={`whitespace-nowrap border-b-2 px-4 py-3 text-sm ${tab===item?'border-red-400 text-white':'border-transparent text-zinc-500 hover:text-zinc-200'}`}>{item}</button>)}</div>
  {tab==='Overview'&&<div className="space-y-5"><AnalystBriefing investigation={inv} findings={inv.findings} graph={graphData}/><div className="grid gap-4 md:grid-cols-4"><div className="glass rounded-2xl p-5"><div className="text-xs text-zinc-500">Target</div><div className="mt-2 break-all font-medium">{inv.target}</div></div><div className="glass rounded-2xl p-5"><div className="text-xs text-zinc-500">Username</div><div className="mt-2 font-medium">{inv.username||'—'}</div></div><div className="glass rounded-2xl p-5"><div className="text-xs text-zinc-500">Domain</div><div className="mt-2 font-medium">{inv.domain||'—'}</div></div><RiskCard score={inv.risk_score} level={inv.risk_level}/></div><RiskDimensions dimensions={dimensions}/><div className="glass rounded-2xl p-5"><div className="font-medium">Execution modules</div><div className="mt-4 grid gap-2 sm:grid-cols-2 lg:grid-cols-3">{modules.map(m=><div key={m.module} className="rounded-xl border border-white/7 bg-white/[.02] p-3"><div className="flex items-center justify-between gap-2"><span className="capitalize text-sm">{m.module.replaceAll('_',' ')}</span><Badge tone={m.status==='completed'?'good':m.status==='failed'?'danger':'warn'}>{m.status}</Badge></div>{m.message&&<div className="mt-1 text-xs text-zinc-600">{m.message}</div>}</div>)}</div></div></div>}
  {tab==='Evidence'&&<EvidenceExplorer findings={inv.findings.filter(f=>f.finding_type!=='risk_dimension'&&f.finding_type!=='provider_status')} onPivot={pivot} focusFindingId={focusFindingId}/>} 
  {tab==='Providers'&&<ProviderStatusGrid findings={providers}/>} 
  {tab==='Timeline'&&<div className="space-y-3"><div className="text-xs text-zinc-500">{timeline.length} timeline event{timeline.length===1?'':'s'} with collection and provenance metadata.</div><Timeline events={timeline}/></div>}
  {tab==='Graph'&&<div className="glass overflow-hidden rounded-2xl"><div className="flex items-center gap-2 border-b border-white/8 px-5 py-4"><Network size={17} className="text-red-400"/><div><div className="font-medium">Evidence graph</div><div className="text-xs text-zinc-500">Relationships remain evidence-backed and probabilistic.</div></div></div><Graph id={inv.id} findings={graphFindings} onEvidence={openGraphEvidence} onPivot={onOpen}/></div>}
  {tab==='Reports'&&<div className="glass rounded-2xl p-6"><div className="flex items-center gap-3"><Download size={18} className="text-red-400"/><div><div className="font-medium">Evidence-preserving reports</div><div className="text-xs text-zinc-500">Use the existing report formats and provenance.</div></div></div><div className="mt-5 grid gap-3 sm:grid-cols-2 lg:grid-cols-4">{['json','csv','html','pdf'].map(format=><button key={format} onClick={()=>report(format)} className="rounded-xl border border-white/10 bg-white/[.03] px-4 py-3 text-sm hover:bg-white/[.06]">Export {format.toUpperCase()}</button>)}</div><div className="mt-5 rounded-xl border border-white/7 bg-white/[.02] p-4 text-xs text-zinc-500">Report generation remains backed by the existing API. No report semantics are changed by the workspace.</div></div>}
  {tab==='Evidence'&&findingCount===0&&<div className="text-xs text-zinc-600">No findings are currently available for the evidence explorer.</div>}
 </div>;
}
