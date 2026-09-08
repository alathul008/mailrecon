import type {Investigation, TimelineEvent} from '../types';

export const API=(import.meta.env.VITE_API_URL||'http://127.0.0.1:8000/api').replace(/\/$/,'');

async function request<T>(path:string, init?:RequestInit):Promise<T>{
  const controller=new AbortController();
  const timer=window.setTimeout(()=>controller.abort(),30000);
  try{
    const r=await fetch(`${API}${path}`,{...init,signal:controller.signal,headers:{...(init?.body?{'content-type':'application/json'}:{}),...(init?.headers||{})}});
    if(!r.ok){let message=`Request failed (${r.status})`;try{const body=await r.json();message=body.detail||body.message||message}catch{}throw new Error(message)}
    return await r.json() as T;
  }catch(e){if(e instanceof DOMException&&e.name==='AbortError')throw new Error('Request timed out. Check that the MailRecon API is running.');throw e}
  finally{window.clearTimeout(timer)}
}

export function createInvestigation(email:string,privacy_mode=false){return request<{id:number;status:string}>('/investigations',{method:'POST',body:JSON.stringify({email,privacy_mode})})}
export function getInvestigation(id:number){return request<Investigation>(`/investigations/${id}`)}
export function listInvestigations(){return request<Array<{id:number;target:string;status:string;risk_score:number|null;risk_level:string|null;created_at:string}>>('/investigations')}
export function getGraph(id:number){return request<{nodes:any[];edges:any[]}>(`/investigations/${id}/graph`)}
export function getTimeline(id:number){return request<TimelineEvent[]>(`/investigations/${id}/timeline`)}
export function reportUrl(id:number,format:string){return `${API}/investigations/${id}/report?format=${encodeURIComponent(format)}`}
