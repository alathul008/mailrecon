import ReactDOMServer from 'react-dom/server';
import {describe,expect,it} from 'vitest';
import {EvidenceExplorer} from './EvidenceExplorer';
import type {Finding} from '../types';

const finding=(overrides:Partial<Finding>):Finding=>({
 id:1,
 source:'DNS',
 source_url:null,
 finding_type:'spf_policy',
 value:'{"present":true}',
 confidence:.99,
 severity:'info',
 evidence_state:'observed',
 execution_id:'execution-1',
 execution_attempt_id:'attempt-1',
 current_attempt:true,
 historical_attempt:false,
 collected_at:'2026-09-12T00:00:00Z',
 first_seen:null,
 last_seen:null,
 notes:'Normalized passive evidence',
 ...overrides,
});

describe('EvidenceExplorer Phase 37 passive intelligence',()=>{
 it('renders normalized passive intelligence and operational separation',()=>{
  const html=ReactDOMServer.renderToStaticMarkup(<EvidenceExplorer findings={[
   finding({finding_type:'spf_policy',evidence_state:'observed'}),
   finding({id:2,finding_type:'mail_service',value:'Google Workspace',evidence_state:'derived'}),
   finding({id:3,source:'Public Web',finding_type:'public_web_reference',value:'https://example.com',evidence_state:'possible_match'}),
   finding({id:4,source:'Gravatar',finding_type:'provider_status',value:'rate_limited',evidence_state:'observed'}),
  ]} onPivot={()=>undefined}/>);
  expect(html).toContain('Passive Intelligence');
  expect(html).toContain('Observed evidence');
  expect(html).toContain('Derived intelligence');
  expect(html).toContain('Operational status');
  expect(html).toContain('Passive only');
  expect(html).toContain('Google Workspace');
  expect(html).toContain('rate_limited');
  expect(html).toContain('These signals do not confirm identity or ownership.');
 });
});
