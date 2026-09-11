import {useState} from 'react';
import {Layout} from './components/Layout';
import {Dashboard} from './pages/Dashboard';
import {Lookup} from './pages/Lookup';
import {Placeholder} from './pages/Placeholder';
import {Graph} from './pages/Graph';
import {Investigations} from './pages/Investigations';
import {Investigation} from './pages/Investigation';

export default function App(){
 const [active,setActive]=useState('Dashboard');
 const [graphId,setGraphId]=useState<number|null>(null);
 const [investigationId,setInvestigationId]=useState<number|null>(null);
 const navigate=(page:string,id?:number)=>{if(id!==undefined){setGraphId(id);setInvestigationId(id)}setActive(page)};
 let page;
 if(active==='Dashboard') page=<Dashboard onLookup={()=>navigate('Email Lookup')}/>;
 else if(active==='Email Lookup') page=<Lookup onGraph={(id)=>navigate('Graph',id)}/>;
 else if(active==='Investigations') page=<Investigations onOpen={(id)=>navigate('Investigation',id)} onNew={()=>navigate('Email Lookup')}/>;
 else if(active==='Investigation'&&investigationId!==null) page=<Investigation id={investigationId} onBack={()=>navigate('Investigations')} onOpen={(id)=>navigate('Investigation',id)}/>;
 else if(active==='Graph') page=graphId?<Graph id={graphId}/>:<Placeholder title="Evidence Graph"/>;
 else page=<Placeholder title={active}/>;
 return <Layout active={active==='Investigation'?'Investigations':active} onNav={(x)=>navigate(x)}>{page}</Layout>;
}
