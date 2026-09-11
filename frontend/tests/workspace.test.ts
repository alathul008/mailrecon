import {describe,expect,it,vi,beforeEach} from 'vitest';
import {filterFindings,filterInvestigations,getPivotTarget,sortInvestigations} from '../src/services/workspace';
import type {Finding} from '../src/types';

const investigations=[
 {id:1,target:'alpha@example.com',status:'completed',risk_score:80,risk_level:'high',created_at:'2026-01-02T00:00:00Z'},
 {id:2,target:'beta@example.com',status:'failed',risk_score:20,risk_level:'low',created_at:'2026-01-03T00:00:00Z'},
 {id:3,target:'gamma@example.com',status:'running',risk_score:null,risk_level:null,created_at:'2026-01-01T00:00:00Z'},
];

const findings:Finding[]=[
 {id:1,source:'github',finding_type:'email_match',value:'alpha@example.com',confidence:.9,severity:'high',collected_at:'2026-01-01T00:00:00Z',evidence_state:'observed',current_attempt:true,execution_attempt_id:'current'},
 {id:2,source:'github',finding_type:'email_match',value:'old@example.com',confidence:.6,severity:'medium',collected_at:'2026-01-01T00:00:00Z',evidence_state:'observed',current_attempt:false,execution_attempt_id:'old'},
 {id:3,source:'dns',finding_type:'mx',value:'mail.example.com',confidence:.8,severity:'info',collected_at:'2026-01-01T00:00:00Z',evidence_state:'observed',current_attempt:true,execution_attempt_id:'current'},
];

describe('investigation workspace helpers',()=>{
 it('searches and filters investigations by target/id, status, and risk',()=>{
  expect(filterInvestigations(investigations,'ALPHA','all','all')).toHaveLength(1);
  expect(filterInvestigations(investigations,'#2','all','all')).toHaveLength(1);
  expect(filterInvestigations(investigations,'','failed','all')[0].id).toBe(2);
  expect(filterInvestigations(investigations,'','all','high')[0].id).toBe(1);
 });
 it('sorts by creation time, risk, and target without mutating input',()=>{
  expect(sortInvestigations(investigations,'created_desc').map(x=>x.id)).toEqual([2,1,3]);
  expect(sortInvestigations(investigations,'risk_desc').map(x=>x.id)).toEqual([1,2,3]);
  expect(sortInvestigations(investigations,'target_asc').map(x=>x.id)).toEqual([1,2,3]);
  expect(investigations.map(x=>x.id)).toEqual([1,2,3]);
 });
});

describe('evidence explorer filters',()=>{
 const base={source:'all',findingType:'all',severity:'all',confidence:'all',evidenceState:'all',execution:'all'} as const;
 it('filters provider, type, severity, confidence, evidence state, and execution history',()=>{
  expect(filterFindings(findings,{...base,source:'github'})).toHaveLength(2);
  expect(filterFindings(findings,{...base,confidence:'high'})).toHaveLength(2);
  expect(filterFindings(findings,{...base,severity:'medium',execution:'historical'})).toHaveLength(1);
  expect(filterFindings(findings,{...base,execution:'current'}).map(x=>x.id)).toEqual([1,3]);
 });
});

describe('explicit analyst pivots',()=>{
 it('allows only email-valued findings to become new investigation targets',()=>{
  expect(getPivotTarget(findings[0])).toBe('alpha@example.com');
  expect(getPivotTarget(findings[2])).toBeNull();
 });
});

// The repository deliberately has no DOM testing dependency. These tests execute the
// actual React components and event handlers with Vitest's existing stack, using a tiny
// deterministic hook/window harness rather than adding a new framework or dependency.
vi.mock('react', async()=>{
 const actual=await vi.importActual<typeof import('react')>('react');
 let state:any[]=[];
 let cursor=0;
 const effects=new Set<number>();
 return {
  ...actual,
  useState:<T>(initial:T)=>{const index=cursor++;if(!(index in state))state[index]=initial;return [state[index],(next:T|((v:T)=>T))=>{state[index]=typeof next==='function'?(next as (v:T)=>T)(state[index]):next}] as const},
  useMemo:<T>(factory:()=>T)=>{cursor++;return factory()},
  useCallback:<T>(callback:T)=>{cursor++;return callback},
  useEffect:(effect:()=>void|(()=>void))=>{const index=cursor++;if(!effects.has(index)){effects.add(index);void effect()}},
  __resetHooks:()=>{state=[];cursor=0;effects.clear()},
  __rewindHooks:()=>{cursor=0},
 };
});

vi.mock('../src/services/api',()=>({
 listInvestigations:vi.fn(),
 deleteInvestigation:vi.fn(),
 getInvestigation:vi.fn(),
 getTimeline:vi.fn(),
 createInvestigation:vi.fn(),
 downloadReport:vi.fn(),
}));

function installWindowHarness(){
 const listeners=new Map<string,Set<() => void>>();
 (globalThis as any).window={
  confirm:vi.fn(()=>true),
  setInterval:vi.fn(()=>1),
  clearInterval:vi.fn(),
  addEventListener:(name:string,fn:()=>void)=>{if(!listeners.has(name))listeners.set(name,new Set());listeners.get(name)!.add(fn)},
  removeEventListener:(name:string,fn:()=>void)=>{listeners.get(name)?.delete(fn)},
  dispatchEvent:(event:Event)=>{listeners.get(event.type)?.forEach(fn=>fn());return true},
 };
}

function textOf(node:any):string{
 if(node==null||typeof node==='boolean')return '';
 if(typeof node==='string'||typeof node==='number')return String(node);
 if(Array.isArray(node))return node.map(textOf).join('');
 if(node.props?.children)return textOf(node.props.children);
 return '';
}
function allElements(node:any):any[]{
 if(node==null||typeof node!=='object')return [];
 if(Array.isArray(node))return node.flatMap(allElements);
 return [node,...allElements(node.props?.children)];
}
function elementsWithText(node:any,text:string){return allElements(node).filter(el=>textOf(el)===text);}
function button(node:any,text:string){const found=elementsWithText(node,text).find(el=>el.type==='button');expect(found,`button ${text}`).toBeTruthy();return found;}

const detailedInvestigation={
 id:1,target:'alpha@example.com',status:'completed',risk_score:80,risk_level:'high',created_at:'2026-01-02T00:00:00Z',username:'alpha',domain:'example.com',
 findings:[
  {...findings[0],source_url:'https://example.com/evidence',notes:'Observed on public source.'},
  {...findings[1]},
  {id:4,source:'github',finding_type:'provider_status',value:'ok',confidence:1,severity:'info',collected_at:'2026-01-01T00:00:00Z',evidence_state:'observed',current_attempt:true,notes:'Provider completed.'},
  {id:5,source:'risk',finding_type:'risk_dimension',value:'exposure=70',confidence:1,severity:'info',collected_at:'2026-01-01T00:00:00Z',evidence_state:'observed',current_attempt:true},
 ],
 modules:[{module:'github',status:'completed',message:'Done'}],
};

beforeEach(async()=>{
 vi.clearAllMocks();
 installWindowHarness();
 const react=await import('react') as typeof import('react') & {__resetHooks:()=>void;__rewindHooks:()=>void};
 react.__resetHooks();
});

describe('Phase 20 investigation workspace UI',()=>{
 it('renders loading, list, search/filter/sort, empty and error states, and opens an investigation',async()=>{
  const api=await import('../src/services/api');
  vi.mocked(api.listInvestigations).mockResolvedValue(investigations);
  const {Investigations}=await import('../src/pages/Investigations');
  const react=await import('react') as typeof import('react') & {__rewindHooks:()=>void};
  react.__rewindHooks();
  const onOpen=vi.fn(); let tree=Investigations({onOpen,onNew:vi.fn()});
  expect(textOf(tree)).toContain('Loading investigations');
  await Promise.resolve(); await Promise.resolve(); react.__rewindHooks();
  tree=Investigations({onOpen,onNew:vi.fn()});
  expect(textOf(tree)).toContain('alpha@example.com');
  const search=allElements(tree).find(el=>el.type==='input'&&el.props?.['aria-label']==='Search investigations');
  expect(search).toBeTruthy(); search.props.onChange({target:{value:'beta'}}); react.__rewindHooks(); tree=Investigations({onOpen,onNew:vi.fn()});
  expect(textOf(tree)).toContain('beta@example.com'); expect(textOf(tree)).not.toContain('alpha@example.com');
  const status=allElements(tree).find(el=>el.type==='select'&&el.props?.['aria-label']==='Filter status');
  status.props.onChange({target:{value:'failed'}}); react.__rewindHooks(); tree=Investigations({onOpen,onNew:vi.fn()}); expect(textOf(tree)).toContain('beta@example.com');
  button(tree,'Open').props.onClick(); expect(onOpen).toHaveBeenCalledWith(2);
  const sort=allElements(tree).find(el=>el.type==='select'&&el.props?.['aria-label']==='Sort investigations'); sort.props.onChange({target:{value:'risk_desc'}}); react.__rewindHooks(); tree=Investigations({onOpen,onNew:vi.fn()}); expect(textOf(tree)).toContain('beta@example.com');
  vi.mocked(api.listInvestigations).mockResolvedValue([]); react.__resetHooks(); react.__rewindHooks(); tree=Investigations({onOpen:vi.fn(),onNew:vi.fn()}); expect(textOf(tree)).toContain('Loading investigations'); await Promise.resolve(); await Promise.resolve(); react.__rewindHooks(); tree=Investigations({onOpen:vi.fn(),onNew:vi.fn()}); expect(textOf(tree)).toContain('No investigations yet');
  vi.mocked(api.listInvestigations).mockRejectedValue(new Error('load failed')); react.__resetHooks(); react.__rewindHooks(); Investigations({onOpen:vi.fn(),onNew:vi.fn()}); await Promise.resolve(); await Promise.resolve(); react.__rewindHooks(); expect(textOf(Investigations({onOpen:vi.fn(),onNew:vi.fn()}))).toContain('load failed');
 });

 it('deletes an investigation after confirmation and removes it from the workspace',async()=>{
  const api=await import('../src/services/api'); vi.mocked(api.listInvestigations).mockResolvedValue(investigations); vi.mocked(api.deleteInvestigation).mockResolvedValue({id:2,status:'deleted'});
  const {Investigations}=await import('../src/pages/Investigations'); const react=await import('react') as typeof import('react') & {__resetHooks:()=>void;__rewindHooks:()=>void}; react.__resetHooks(); react.__rewindHooks(); Investigations({onOpen:vi.fn(),onNew:vi.fn()}); await Promise.resolve(); await Promise.resolve(); react.__rewindHooks(); let tree=Investigations({onOpen:vi.fn(),onNew:vi.fn()}); const betaRow=allElements(tree).find(el=>el.type==='tr'&&textOf(el).includes('beta@example.com')); expect(betaRow).toBeTruthy(); const deleteButton=allElements(betaRow).find(el=>el.type==='button'&&textOf(el).includes('Delete')); expect(deleteButton).toBeTruthy(); await deleteButton.props.onClick(); expect(window.confirm).toHaveBeenCalledWith(expect.stringContaining('Permanently delete investigation #2')); expect(api.deleteInvestigation).toHaveBeenCalledWith(2); react.__rewindHooks(); tree=Investigations({onOpen:vi.fn(),onNew:vi.fn()}); expect(textOf(tree)).not.toContain('beta@example.com');
 });
});

describe('Phase 20 detail, evidence, provider, execution, pivot and reports UI',()=>{
 it('renders detail tabs and finding provenance including current and historical execution',async()=>{
  const api=await import('../src/services/api'); vi.mocked(api.getInvestigation).mockResolvedValue(detailedInvestigation as any); vi.mocked(api.getTimeline).mockResolvedValue([{id:1,event_type:'collection',message:'Collected',created_at:'2026-01-02T00:00:00Z',execution_attempt_id:'current'}] as any);
  const {Investigation}=await import('../src/pages/Investigation'); const react=await import('react') as typeof import('react') & {__resetHooks:()=>void;__rewindHooks:()=>void}; react.__resetHooks(); react.__rewindHooks(); let tree=Investigation({id:1,onBack:vi.fn(),onOpen:vi.fn()}); expect(textOf(tree)).toContain('Loading investigation #1'); await Promise.resolve(); await Promise.resolve(); react.__rewindHooks(); tree=Investigation({id:1,onBack:vi.fn(),onOpen:vi.fn()});
  for(const tab of ['Overview','Evidence','Providers','Timeline','Graph','Reports'])expect(textOf(tree)).toContain(tab);
  button(tree,'Evidence').props.onClick(); react.__rewindHooks(); tree=Investigation({id:1,onBack:vi.fn(),onOpen:vi.fn()}); expect(textOf(tree)).toContain('Evidence explorer'); expect(textOf(tree)).toContain('current'); expect(textOf(tree)).toContain('old');
  const row=allElements(tree).find(el=>el.type==='tr'&&textOf(el).includes('alpha@example.com')); expect(row).toBeTruthy(); row.props.onClick(); react.__rewindHooks(); tree=Investigation({id:1,onBack:vi.fn(),onOpen:vi.fn()}); expect(textOf(tree)).toContain('Finding detail'); expect(textOf(tree)).toContain('Execution attempt'); expect(textOf(tree)).toContain('Observed on public source.');
  const executionStates=['queued','running','completed','failed','abandoned','recovered']; const {ExecutionStatus}=await import('../src/components/ExecutionStatus'); for(const state of executionStates)expect(textOf(ExecutionStatus({status:state}))).toContain(state);
  const {ProviderStatusGrid}=await import('../src/components/ProviderStatusGrid'); const providerFindings=['ok','unconfigured','rate_limited','unavailable','error','disabled'].map((value,index)=>({...findings[2],id:20+index,source:`provider-${value}`,finding_type:'provider_status',value})); const providerTree=ProviderStatusGrid({findings:providerFindings}); for(const state of ['ok','unconfigured','rate_limited','unavailable','error','disabled'])expect(textOf(providerTree)).toContain(state); expect(textOf(providerTree)).toContain('provider failure is not a negative result');
 });

 it('allows only email findings to pivot, creates a separate investigation, and never claims identity confirmation',async()=>{
  const api=await import('../src/services/api'); vi.mocked(api.getInvestigation).mockResolvedValue(detailedInvestigation as any); vi.mocked(api.getTimeline).mockResolvedValue([] as any); vi.mocked(api.createInvestigation).mockResolvedValue({id:9,status:'queued'});
  const {Investigation}=await import('../src/pages/Investigation'); const react=await import('react') as typeof import('react') & {__resetHooks:()=>void;__rewindHooks:()=>void}; const onOpen=vi.fn(); react.__resetHooks(); react.__rewindHooks(); let tree=Investigation({id:1,onBack:vi.fn(),onOpen}); await Promise.resolve(); await Promise.resolve(); react.__rewindHooks(); tree=Investigation({id:1,onBack:vi.fn(),onOpen}); button(tree,'Evidence').props.onClick(); react.__rewindHooks(); tree=Investigation({id:1,onBack:vi.fn(),onOpen}); allElements(tree).find(el=>el.type==='tr'&&textOf(el).includes('alpha@example.com')).props.onClick(); react.__rewindHooks(); tree=Investigation({id:1,onBack:vi.fn(),onOpen}); const pivot=button(tree,'Pivot to separate investigation'); expect(pivot.props.disabled).toBe(false); await pivot.props.onClick(); expect(api.createInvestigation).toHaveBeenCalledWith('alpha@example.com',false,true); expect(onOpen).toHaveBeenCalledWith(9); expect(textOf(tree)).toContain('never confirms identity or merges investigations');
  react.__rewindHooks(); tree=Investigation({id:1,onBack:vi.fn(),onOpen}); const dnsRow=allElements(tree).find(el=>el.type==='tr'&&textOf(el).includes('mail.example.com')); expect(dnsRow).toBeTruthy(); dnsRow.props.onClick(); react.__rewindHooks(); tree=Investigation({id:1,onBack:vi.fn(),onOpen}); expect(button(tree,'Pivot to separate investigation').props.disabled).toBe(true);
 });

 it('renders report actions and invokes the existing report API, and handles auth-required events',async()=>{
  const api=await import('../src/services/api'); vi.mocked(api.getInvestigation).mockResolvedValue(detailedInvestigation as any); vi.mocked(api.getTimeline).mockResolvedValue([] as any); vi.mocked(api.downloadReport).mockResolvedValue(undefined);
  const {Investigation}=await import('../src/pages/Investigation'); const react=await import('react') as typeof import('react') & {__resetHooks:()=>void;__rewindHooks:()=>void}; const onBack=vi.fn(); react.__resetHooks(); react.__rewindHooks(); Investigation({id:1,onBack,onOpen:vi.fn()}); await Promise.resolve(); await Promise.resolve(); react.__rewindHooks(); let tree=Investigation({id:1,onBack,onOpen:vi.fn()}); button(tree,'Reports').props.onClick(); react.__rewindHooks(); tree=Investigation({id:1,onBack,onOpen:vi.fn()}); for(const format of ['JSON','CSV','HTML','PDF'])expect(textOf(tree)).toContain(`Export ${format}`); const exportJson=button(tree,'Export JSON'); await exportJson.props.onClick(); expect(api.downloadReport).toHaveBeenCalledWith(1,'json');
  react.__rewindHooks(); tree=Investigation({id:1,onBack,onOpen:vi.fn()}); (globalThis as any).window.dispatchEvent(new Event('mailrecon:auth-required')); react.__rewindHooks(); tree=Investigation({id:1,onBack,onOpen:vi.fn()}); expect(textOf(tree)).toContain('Authentication required. Enter your MailRecon API key before continuing.');
 });

 it('handles authentication-required and deletion errors in the detail workspace',async()=>{
  const api=await import('../src/services/api'); vi.mocked(api.getInvestigation).mockResolvedValue(detailedInvestigation as any); vi.mocked(api.getTimeline).mockResolvedValue([] as any); vi.mocked(api.deleteInvestigation).mockRejectedValue(new Error('delete unauthorized'));
  const {Investigation}=await import('../src/pages/Investigation'); const react=await import('react') as typeof import('react') & {__resetHooks:()=>void;__rewindHooks:()=>void}; const onBack=vi.fn(); react.__resetHooks(); react.__rewindHooks(); Investigation({id:1,onBack,onOpen:vi.fn()}); await Promise.resolve(); await Promise.resolve(); react.__rewindHooks(); let tree=Investigation({id:1,onBack,onOpen:vi.fn()}); await button(tree,'Delete').props.onClick(); await Promise.resolve(); react.__rewindHooks(); tree=Investigation({id:1,onBack,onOpen:vi.fn()}); expect(textOf(tree)).toContain('delete unauthorized'); expect(onBack).not.toHaveBeenCalled();
  (globalThis as any).window.dispatchEvent(new Event('mailrecon:auth-required')); react.__rewindHooks(); tree=Investigation({id:1,onBack,onOpen:vi.fn()}); expect(textOf(tree)).toContain('Authentication required. Enter your MailRecon API key before continuing.');
 });
});
