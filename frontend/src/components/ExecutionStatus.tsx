import {CheckCircle2,Clock3,LoaderCircle,OctagonAlert,RotateCcw} from 'lucide-react';
import {Badge} from './Badge';

const states=['queued','running','completed','failed','abandoned','recovered'] as const;
function tone(state:string){return state==='completed'||state==='recovered'?'good':state==='failed'||state==='abandoned'?'danger':state==='running'?'warn':'neutral'}
function icon(state:string){if(state==='completed')return <CheckCircle2 size={15}/>;if(state==='running')return <LoaderCircle className="animate-spin" size={15}/>;if(state==='failed'||state==='abandoned')return <OctagonAlert size={15}/>;if(state==='recovered')return <RotateCcw size={15}/>;return <Clock3 size={15}/>}
export function ExecutionStatus({status}:{status:string}){return <div className="flex flex-wrap items-center gap-2" aria-label="Execution status"><Badge tone={tone(status)}><span className="inline-flex items-center gap-1.5">{icon(status)}{states.includes(status as typeof states[number])?status:'unknown'}</span></Badge></div>}
