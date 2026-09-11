import type { GraphData, GraphEdge, GraphNode } from './api';

export type GraphFilters = {
  nodeType: string;
  relation: string;
  minConfidence: number;
};

export type GraphNeighborhood = {
  nodeIds: string[];
  edgeIds: string[];
};

export function graphNodeTypes(graph: GraphData) {
  return Array.from(new Set(graph.nodes.map((node) => node.type))).sort();
}

export function graphRelations(graph: GraphData) {
  return Array.from(new Set(graph.edges.map((edge) => edge.relation))).sort();
}

export function filterGraph(graph: GraphData, filters: GraphFilters): GraphData {
  const allowedNodes = new Set(
    graph.nodes
      .filter((node) => filters.nodeType === 'all' || node.type === filters.nodeType)
      .map((node) => node.id),
  );

  const edges = graph.edges.filter(
    (edge) =>
      edge.confidence >= filters.minConfidence &&
      allowedNodes.has(edge.source) &&
      allowedNodes.has(edge.target) &&
      (filters.relation === 'all' || edge.relation === filters.relation),
  );

  const connectedIds = new Set<string>();
  edges.forEach((edge) => {
    connectedIds.add(edge.source);
    connectedIds.add(edge.target);
  });

  const nodes = graph.nodes.filter(
    (node) => allowedNodes.has(node.id) && (connectedIds.size === 0 || connectedIds.has(node.id)),
  );

  return { nodes, edges };
}

export function neighborhood(graph: GraphData, centerId: string, depth = 1): GraphNeighborhood {
  if (!graph.nodes.some((node) => node.id === centerId) || depth < 0) {
    return { nodeIds: [], edgeIds: [] };
  }

  const distances = new Map<string, number>([[centerId, 0]]);
  const queue = [centerId];
  const edgeIds: string[] = [];

  while (queue.length) {
    const current = queue.shift()!;
    const distance = distances.get(current)!;
    if (distance >= depth) continue;

    graph.edges.forEach((edge, index) => {
      if (edge.source !== current && edge.target !== current) return;
      edgeIds.push(String(index));
      const next = edge.source === current ? edge.target : edge.source;
      if (!distances.has(next)) {
        distances.set(next, distance + 1);
        queue.push(next);
      }
    });
  }

  return {
    nodeIds: Array.from(distances.keys()),
    edgeIds: Array.from(new Set(edgeIds)),
  };
}

export function shortestPath(graph: GraphData, startId: string, endId: string) {
  if (startId === endId && graph.nodes.some((node) => node.id === startId)) return [startId];
  if (!graph.nodes.some((node) => node.id === startId) || !graph.nodes.some((node) => node.id === endId)) {
    return [];
  }

  const previous = new Map<string, string | null>([[startId, null]]);
  const queue = [startId];

  while (queue.length) {
    const current = queue.shift()!;
    const neighbors = graph.edges.flatMap((edge) => {
      if (edge.source === current) return [edge.target];
      if (edge.target === current) return [edge.source];
      return [];
    });

    for (const next of neighbors) {
      if (previous.has(next)) continue;
      previous.set(next, current);
      if (next === endId) {
        const path: string[] = [];
        let cursor: string | null = endId;
        while (cursor) {
          path.unshift(cursor);
          cursor = previous.get(cursor) ?? null;
        }
        return path;
      }
      queue.push(next);
    }
  }

  return [];
}

export function graphEvidenceCandidates(nodes: GraphNode[], findings: Array<{ id: number; value: string }>) {
  return nodes.flatMap((node) => {
    const candidates = findings.filter(
      (finding) => finding.value === node.label || node.id.endsWith(`:${finding.value}`),
    );
    return candidates.length ? [{ nodeId: node.id, findingIds: candidates.map((finding) => finding.id) }] : [];
  });
}

export function edgeIdentity(edge: GraphEdge, index: number) {
  return `${edge.source}|${edge.target}|${edge.relation}|${index}`;
}
