import type {Finding} from '../types';

export type InvestigationSummary={id:number;target:string;status:string;risk_score:number|null;risk_level:string|null;created_at:string};
export type SortKey='created_desc'|'created_asc'|'risk_desc'|'risk_asc'|'target_asc';

export function filterInvestigations(items:InvestigationSummary[],query:string,status:string,risk:string){
 const q=query.trim().toLowerCase().replace(/^#/,'');
 return items.filter(item=>{
  const matchesQuery=!q||item.target.toLowerCase().includes(q)||String(item.id).includes(q);
  const matchesStatus=status==='all'||item.status===status;
  const matchesRisk=risk==='all'||(item.risk_level||'unknown')===risk;
  return matchesQuery&&matchesStatus&&matchesRisk;
 });
}

export function sortInvestigations(items:InvestigationSummary[],sort:SortKey){
 return [...items].sort((a,b)=>{
  if(sort==='target_asc') return a.target.localeCompare(b.target);
  if(sort==='risk_desc'||sort==='risk_asc'){
   const av=a.risk_score??-1,bv=b.risk_score??-1;
   return sort==='risk_desc'?bv-av:av-bv;
  }
  const delta=new Date(a.created_at).getTime()-new Date(b.created_at).getTime();
  return sort==='created_asc'?delta:-delta;
 });
}

export type EvidenceFilters={source:string;findingType:string;severity:string;confidence:string;evidenceState:string;execution:string};

export function filterFindings(findings:Finding[],filters:EvidenceFilters){
 return findings.filter(f=>{
  const current=f.current_attempt===true;
  const historical=f.current_attempt===false;
  const confidence=filters.confidence==='all'||(filters.confidence==='high'&&f.confidence>=0.75)||(filters.confidence==='medium'&&f.confidence>=0.5&&f.confidence<0.75)||(filters.confidence==='low'&&f.confidence<0.5);
  const execution=filters.execution==='all'||(filters.execution==='current'&&current)||(filters.execution==='historical'&&historical);
  return (filters.source==='all'||f.source===filters.source)&&
   (filters.findingType==='all'||f.finding_type===filters.findingType)&&
   (filters.severity==='all'||f.severity===filters.severity)&&confidence&&
   (filters.evidenceState==='all'||(f.evidence_state||'unknown')===filters.evidenceState)&&execution;
 });
}

export function getPivotTarget(finding:Finding){
 const candidate=finding.value.trim();
 return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(candidate)?candidate:null;
}
