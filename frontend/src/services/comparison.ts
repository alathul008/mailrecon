import type { Finding, Investigation } from '../types';

export type FindingChange = {
  key: string;
  findingType: string;
  source: string;
  value: string;
  status: 'added' | 'removed' | 'unchanged' | 'changed';
  before?: Finding;
  after?: Finding;
};

function keyOf(finding: Finding) {
  return `${finding.source}\u001f${finding.finding_type}\u001f${finding.value}`;
}

export function compareFindings(before: Finding[], after: Finding[]): FindingChange[] {
  const left = new Map<string, Finding>(before.filter(f => f.finding_type !== 'risk_dimension' && f.finding_type !== 'provider_status').map(f => [keyOf(f), f]));
  const right = new Map<string, Finding>(after.filter(f => f.finding_type !== 'risk_dimension' && f.finding_type !== 'provider_status').map(f => [keyOf(f), f]));
  const keys = Array.from(new Set([...left.keys(), ...right.keys()]));
  const changes: FindingChange[] = [];
  for (const key of keys) {
    const beforeFinding = left.get(key);
    const afterFinding = right.get(key);
    if (!beforeFinding && afterFinding) changes.push({ key, findingType: afterFinding.finding_type, source: afterFinding.source, value: afterFinding.value, status: 'added', after: afterFinding });
    else if (beforeFinding && !afterFinding) changes.push({ key, findingType: beforeFinding.finding_type, source: beforeFinding.source, value: beforeFinding.value, status: 'removed', before: beforeFinding });
    else if (beforeFinding && afterFinding) {
      const changed = beforeFinding.confidence !== afterFinding.confidence || beforeFinding.severity !== afterFinding.severity || beforeFinding.evidence_state !== afterFinding.evidence_state;
      changes.push({ key, findingType: afterFinding.finding_type, source: afterFinding.source, value: afterFinding.value, status: changed ? 'changed' : 'unchanged', before: beforeFinding, after: afterFinding });
    }
  }
  return changes.sort((a, b) => a.status.localeCompare(b.status) || a.findingType.localeCompare(b.findingType) || a.value.localeCompare(b.value));
}

export function riskDimensionMap(investigation: Investigation) {
  return Object.fromEntries(investigation.findings.filter(f => f.finding_type === 'risk_dimension').flatMap(f => {
    const index = f.value.indexOf('=');
    if (index < 1) return [];
    const value = Number(f.value.slice(index + 1));
    return Number.isFinite(value) ? [[f.value.slice(0, index), value]] : [];
  }));
}

export function findingCounts(changes: FindingChange[]) {
  return changes.reduce((counts, change) => { counts[change.status] += 1; return counts; }, { added: 0, removed: 0, changed: 0, unchanged: 0 });
}
