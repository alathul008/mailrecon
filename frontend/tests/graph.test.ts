import { describe, expect, it } from 'vitest';
import { filterGraph, graphEvidenceCandidates, graphNodeTypes, graphRelations, neighborhood, shortestPath } from '../src/services/graph';
import type { GraphData } from '../src/services/api';

const graph: GraphData = {
  semantics: 'current_derived_view',
  provenance: { type: 'producing_execution_attempt', execution_attempt_id: 'attempt-1' },
  nodes: [
    { id: 'email:a@example.com', type: 'EMAIL', label: 'a@example.com' },
    { id: 'domain:example.com', type: 'DOMAIN', label: 'example.com' },
    { id: 'profile:a', type: 'PROFILE', label: 'profile-a', metadata: { evidence_state: 'possible_match', confidence: 0.72 } },
    { id: 'ip:1.2.3.4', type: 'IP', label: '1.2.3.4' },
  ],
  edges: [
    { source: 'email:a@example.com', target: 'domain:example.com', relation: 'uses', confidence: 1 },
    { source: 'email:a@example.com', target: 'profile:a', relation: 'possible_profile', confidence: 0.72 },
    { source: 'domain:example.com', target: 'ip:1.2.3.4', relation: 'resolves_to', confidence: 0.4 },
  ],
};

describe('graph intelligence helpers', () => {
  it('returns deterministic node types and relationships', () => {
    expect(graphNodeTypes(graph)).toEqual(['DOMAIN', 'EMAIL', 'IP', 'PROFILE']);
    expect(graphRelations(graph)).toEqual(['possible_profile', 'resolves_to', 'uses']);
  });

  it('filters by type, relationship, and confidence without changing source graph', () => {
    const filtered = filterGraph(graph, { nodeType: 'EMAIL', relation: 'uses', minConfidence: 0.5 });
    expect(filtered.nodes.map((node) => node.id)).toEqual(['email:a@example.com']);
    expect(filtered.edges).toEqual([]);
    expect(graph.edges).toHaveLength(3);
  });

  it('computes a deterministic one-hop neighborhood', () => {
    expect(neighborhood(graph, 'email:a@example.com', 1)).toEqual({
      nodeIds: ['email:a@example.com', 'domain:example.com', 'profile:a'],
      edgeIds: ['0', '1'],
    });
  });

  it('finds a shortest undirected relationship path', () => {
    expect(shortestPath(graph, 'profile:a', 'ip:1.2.3.4')).toEqual([
      'profile:a',
      'email:a@example.com',
      'domain:example.com',
      'ip:1.2.3.4',
    ]);
    expect(shortestPath(graph, 'profile:a', 'missing')).toEqual([]);
  });

  it('links graph entities to exact persisted evidence values', () => {
    expect(graphEvidenceCandidates(graph.nodes, [
      { id: 10, value: 'a@example.com' },
      { id: 11, value: 'profile-a' },
      { id: 12, value: 'unrelated' },
    ])).toEqual([
      { nodeId: 'email:a@example.com', findingIds: [10] },
      { nodeId: 'profile:a', findingIds: [11] },
    ]);
  });
});
