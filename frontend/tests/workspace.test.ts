import {describe,expect,it} from 'vitest';
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
