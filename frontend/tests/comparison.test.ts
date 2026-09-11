import { describe, expect, it } from 'vitest';
import { compareFindings, findingCounts, riskDimensionMap } from '../src/services/comparison';
import type { Finding, Investigation } from '../src/types';

const finding = (overrides: Partial<Finding> = {}): Finding => ({ id: 1, source: 'DNS', finding_type: 'mx', value: 'mail.example.com', confidence: 1, severity: 'info', collected_at: '2026-01-01T00:00:00Z', ...overrides });

const investigation = (findings: Finding[]): Investigation => ({ id: 1, target: 'a@example.com', username: 'a', domain: 'example.com', status: 'completed', risk_score: 20, risk_level: 'LOW', created_at: '2026-01-01T00:00:00Z', modules: [], findings });

describe('investigation comparison', () => {
  it('classifies added, removed, changed and unchanged evidence deterministically', () => {
    const unchanged = finding();
    const changed = finding({ id: 2, finding_type: 'spf', value: 'v=spf1 -all', confidence: .5 });
    const added = finding({ id: 3, finding_type: 'dmarc', value: 'v=DMARC1; p=reject' });
    const removed = finding({ id: 4, finding_type: 'aaaa', value: '2001:db8::1' });
    const changes = compareFindings([unchanged, changed, removed], [unchanged, finding({ ...changed, confidence: .9 }), added]);
    expect(findingCounts(changes)).toEqual({ added: 1, removed: 1, changed: 1, unchanged: 1 });
    expect(changes.find(x => x.value === 'v=spf1 -all')?.status).toBe('changed');
    expect(changes.find(x => x.value === '2001:db8::1')?.status).toBe('removed');
    expect(changes.find(x => x.value === 'v=DMARC1; p=reject')?.status).toBe('added');
  });

  it('uses source, finding type and value as evidence identity and excludes derived status rows', () => {
    const a = finding({ source: 'Provider A' });
    const b = finding({ source: 'Provider B' });
    const status = finding({ finding_type: 'provider_status', value: 'ok' });
    expect(compareFindings([a, status], [b, status])).toHaveLength(2);
    expect(compareFindings([a], [finding({ source: 'Provider A', confidence: .5 })])[0].status).toBe('changed');
  });

  it('extracts valid persisted risk dimensions without recomputing risk', () => {
    const result = riskDimensionMap(investigation([finding({ finding_type: 'risk_dimension', value: 'breach=30' }), finding({ finding_type: 'risk_dimension', value: 'bad' })]));
    expect(result).toEqual({ breach: 30 });
  });
});
