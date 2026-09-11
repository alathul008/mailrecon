import { describe, expect, it } from 'vitest';
import { selectNotableFindings } from '../src/components/AnalystBriefing';
import type { Finding } from '../src/types';

const finding = (id: number, severity: string, confidence: number, finding_type = 'profile_candidate'): Finding => ({
  id,
  source: 'Test Provider',
  finding_type,
  value: `value-${id}`,
  confidence,
  severity,
  collected_at: '2026-01-01T00:00:00Z',
});

describe('analyst briefing helpers', () => {
  it('selects notable findings deterministically by severity, confidence, then id', () => {
    expect(selectNotableFindings([
      finding(4, 'medium', 0.99),
      finding(2, 'high', 0.60),
      finding(3, 'high', 0.90),
      finding(1, 'critical', 0.40),
      finding(5, 'low', 1.0),
      finding(6, 'info', 1.0),
    ], 4).map((item) => item.id)).toEqual([1, 3, 2, 4]);
  });

  it('excludes risk dimensions and provider status from observed-finding briefing candidates', () => {
    expect(selectNotableFindings([
      finding(1, 'critical', 1, 'risk_dimension'),
      finding(2, 'high', 1, 'provider_status'),
      finding(3, 'medium', 0.8, 'breach'),
    ]).map((item) => item.id)).toEqual([3]);
  });

  it('does not mutate the persisted finding order', () => {
    const findings = [finding(2, 'low', 0.5), finding(1, 'high', 0.5)];
    selectNotableFindings(findings);
    expect(findings.map((item) => item.id)).toEqual([2, 1]);
  });
});
