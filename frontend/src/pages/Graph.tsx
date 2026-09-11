import { useEffect, useMemo, useState } from 'react';
import {
  ReactFlow,
  Background,
  Controls,
  MiniMap,
  Handle,
  Position,
  type Edge,
  type Node,
  type NodeMouseHandler,
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import { ArrowRight, Crosshair, ExternalLink, Filter, Network, RotateCcw, Search } from 'lucide-react';
import { createInvestigation, getGraph, type GraphData, type GraphNode } from '../services/api';
import { graphNodeTypes, graphRelations, neighborhood, shortestPath, type GraphFilters } from '../services/graph';

const initialFilters: GraphFilters = { nodeType: 'all', relation: 'all', minConfidence: 0 };
const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

export function Graph({
  id,
  onEvidence,
  onPivot,
}: {
  id: number;
  onEvidence?: (node: GraphNode) => void;
  onPivot?: (investigationId: number) => void;
}) {
  const [graph, setGraph] = useState<GraphData>({ nodes: [], edges: [] });
  const [selectedId, setSelectedId] = useState('');
  const [focusId, setFocusId] = useState('');
  const [filters, setFilters] = useState<GraphFilters>(initialFilters);
  const [error, setError] = useState('');
  const [pivoting, setPivoting] = useState(false);

  useEffect(() => {
    let active = true;
    setError('');
    setSelectedId('');
    setFocusId('');
    getGraph(id)
      .then((data) => {
        if (active) setGraph(data);
      })
      .catch((e) => {
        if (active) setError(e instanceof Error ? e.message : 'Unable to load graph');
      });
    return () => {
      active = false;
    };
  }, [id]);

  const visible = useMemo(() => {
    const allowedTypes = new Set(
      graph.nodes
        .filter((node) => filters.nodeType === 'all' || node.type === filters.nodeType)
        .map((node) => node.id),
    );
    const edges = graph.edges.filter(
      (edge) =>
        edge.confidence >= filters.minConfidence &&
        allowedTypes.has(edge.source) &&
        allowedTypes.has(edge.target) &&
        (filters.relation === 'all' || edge.relation === filters.relation),
    );
    const ids = new Set<string>();
    edges.forEach((edge) => {
      ids.add(edge.source);
      ids.add(edge.target);
    });
    const nodes = graph.nodes.filter((node) => allowedTypes.has(node.id) && (ids.size === 0 || ids.has(node.id)));
    return { nodes, edges };
  }, [graph, filters]);

  const neighborhoodIds = useMemo(
    () => (focusId ? new Set(neighborhood(visible, focusId, 1).nodeIds) : new Set<string>()),
    [visible, focusId],
  );

  const path = useMemo(
    () => (selectedId && focusId ? shortestPath(visible, selectedId, focusId) : []),
    [visible, selectedId, focusId],
  );

  const nodes: Node[] = useMemo(
    () =>
      visible.nodes.map((node, index) => {
        const selected = node.id === selectedId;
        const focused = node.id === focusId;
        const dimmed = Boolean(focusId) && !neighborhoodIds.has(node.id);
        return {
          id: node.id,
          position: { x: (index % 4) * 260, y: Math.floor(index / 4) * 170 },
          data: {
            label: (
              <div
                className={`min-w-40 rounded-xl border px-4 py-3 text-xs shadow-xl ${
                  selected || focused ? 'border-red-400/70 bg-[#171111]' : 'border-white/10 bg-[#101010]'
                } ${dimmed ? 'opacity-25' : ''}`}
              >
                <Handle type="target" position={Position.Top} className="opacity-0" />
                <div className="text-[9px] tracking-widest text-red-400">{node.type}</div>
                <div className="mt-1 max-w-48 break-words text-white">{node.label}</div>
                {typeof node.metadata?.confidence === 'number' && (
                  <div className="mt-2 text-[10px] text-zinc-500">
                    Confidence {Math.round(node.metadata.confidence * 100)}%
                  </div>
                )}
                <Handle type="source" position={Position.Bottom} className="opacity-0" />
              </div>
            ),
          },
          style: { opacity: dimmed ? 0.25 : 1 },
        };
      }),
    [visible.nodes, selectedId, focusId, neighborhoodIds],
  );

  const edges: Edge[] = useMemo(
    () =>
      visible.edges.map((edge, index) => {
        const inPath = path.length > 1 && path.includes(edge.source) && path.includes(edge.target);
        return {
          id: `${edge.source}|${edge.target}|${edge.relation}|${index}`,
          source: edge.source,
          target: edge.target,
          label: `${edge.relation} · ${Math.round(edge.confidence * 100)}%`,
          animated: inPath,
          style: { opacity: focusId && !neighborhoodIds.has(edge.source) && !neighborhoodIds.has(edge.target) ? 0.15 : 1 },
        };
      }),
    [visible.edges, path, focusId, neighborhoodIds],
  );

  const selectedNode = graph.nodes.find((node) => node.id === selectedId) || null;
  const focusedNode = graph.nodes.find((node) => node.id === focusId) || null;
  const types = useMemo(() => graphNodeTypes(graph), [graph]);
  const relations = useMemo(() => graphRelations(graph), [graph]);

  const selectNode: NodeMouseHandler = (_event, node) => setSelectedId(node.id);

  function resetFilters() {
    setFilters(initialFilters);
    setSelectedId('');
    setFocusId('');
  }

  async function pivotEmail() {
    if (!selectedNode || selectedNode.type !== 'EMAIL' || !emailPattern.test(selectedNode.label.trim())) return;
    setPivoting(true);
    setError('');
    try {
      const created = await createInvestigation(selectedNode.label.trim(), false, true);
      onPivot?.(created.id);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Unable to create pivot investigation');
    } finally {
      setPivoting(false);
    }
  }

  return (
    <div className="grid h-[650px] min-h-0 lg:grid-cols-[1fr_340px]">
      <div className="relative min-h-0">
        {error && <div role="alert" className="absolute left-4 right-4 top-4 z-10 rounded-xl border border-red-500/20 bg-red-500/10 p-3 text-xs text-red-300">{error}</div>}
        <ReactFlow nodes={nodes} edges={edges} fitView onNodeClick={selectNode} onPaneClick={() => setSelectedId('')}>
          <Background gap={24} />
          <MiniMap />
          <Controls />
        </ReactFlow>
      </div>
      <aside className="overflow-y-auto border-t border-white/8 bg-[#0c0c0c] p-5 lg:border-l lg:border-t-0">
        <div className="flex items-center gap-2"><Network size={16} className="text-red-400" /><div><div className="font-medium">Graph investigation</div><div className="text-xs text-zinc-500">Select, focus, filter, and inspect evidence-backed relationships.</div></div></div>

        <div className="mt-5 space-y-2">
          <label className="flex items-center gap-2 rounded-lg border border-white/10 bg-white/[.02] px-3 py-2 text-xs"><Filter size={13} className="text-zinc-500" /><select aria-label="Graph node type" value={filters.nodeType} onChange={(e) => setFilters((current) => ({ ...current, nodeType: e.target.value }))} className="w-full bg-transparent outline-none"><option value="all">All node types</option>{types.map((type) => <option key={type}>{type}</option>)}</select></label>
          <label className="flex items-center gap-2 rounded-lg border border-white/10 bg-white/[.02] px-3 py-2 text-xs"><ArrowRight size={13} className="text-zinc-500" /><select aria-label="Graph relationship" value={filters.relation} onChange={(e) => setFilters((current) => ({ ...current, relation: e.target.value }))} className="w-full bg-transparent outline-none"><option value="all">All relationships</option>{relations.map((relation) => <option key={relation}>{relation}</option>)}</select></label>
          <label className="block rounded-lg border border-white/10 bg-white/[.02] px-3 py-2 text-xs"><div className="flex justify-between text-zinc-500"><span>Minimum confidence</span><span>{Math.round(filters.minConfidence * 100)}%</span></div><input aria-label="Minimum graph confidence" type="range" min="0" max="1" step="0.05" value={filters.minConfidence} onChange={(e) => setFilters((current) => ({ ...current, minConfidence: Number(e.target.value) }))} className="mt-2 w-full" /></label>
          <button onClick={resetFilters} className="inline-flex w-full items-center justify-center gap-2 rounded-lg border border-white/10 px-3 py-2 text-xs hover:bg-white/[.05]"><RotateCcw size={13} /> Reset graph</button>
        </div>

        {selectedNode ? (
          <div className="mt-5 rounded-xl border border-white/10 bg-white/[.02] p-4">
            <div className="text-[10px] uppercase tracking-[.18em] text-red-400">Selected entity</div>
            <div className="mt-2 font-semibold break-words">{selectedNode.label}</div>
            <div className="mt-1 text-xs text-zinc-500">{selectedNode.type}</div>
            {typeof selectedNode.metadata?.evidence_state === 'string' && <div className="mt-3 text-xs text-zinc-400">Evidence state: {selectedNode.metadata.evidence_state}</div>}
            {typeof selectedNode.metadata?.confidence === 'number' && <div className="mt-1 text-xs text-zinc-400">Confidence: {Math.round(selectedNode.metadata.confidence * 100)}%</div>}
            <div className="mt-4 grid gap-2">
              <button onClick={() => setFocusId(selectedNode.id)} className="inline-flex items-center justify-center gap-2 rounded-lg border border-white/10 px-3 py-2 text-xs hover:bg-white/[.05]"><Crosshair size={13} /> Focus neighborhood</button>
              {onEvidence && <button onClick={() => onEvidence(selectedNode)} className="inline-flex items-center justify-center gap-2 rounded-lg border border-white/10 px-3 py-2 text-xs hover:bg-white/[.05]"><Search size={13} /> Open related evidence</button>}
              {selectedNode.type === 'EMAIL' && onPivot && <button onClick={pivotEmail} disabled={pivoting || !emailPattern.test(selectedNode.label.trim())} className="inline-flex items-center justify-center gap-2 rounded-lg border border-red-500/20 px-3 py-2 text-xs text-red-300 hover:bg-red-500/10 disabled:opacity-40">{pivoting ? 'Starting pivot…' : 'Pivot email'}</button>}
              {selectedNode.metadata?.source_url && typeof selectedNode.metadata.source_url === 'string' && <a href={selectedNode.metadata.source_url} target="_blank" rel="noreferrer" className="inline-flex items-center justify-center gap-2 rounded-lg border border-white/10 px-3 py-2 text-xs hover:bg-white/[.05]"><ExternalLink size={13} /> Open provenance source</a>}
            </div>
          </div>
        ) : (
          <div className="mt-5 rounded-xl border border-dashed border-white/10 p-5 text-center text-xs text-zinc-600">Select an entity to inspect its evidence and pivots.</div>
        )}

        {focusedNode && (
          <div className="mt-4 rounded-xl border border-white/10 bg-white/[.02] p-4 text-xs">
            <div className="font-medium">Focused neighborhood</div>
            <div className="mt-1 break-words text-zinc-400">{focusedNode.label}</div>
            <div className="mt-3 text-zinc-500">{neighborhoodIds.size} nearby entities</div>
            {selectedId && selectedId !== focusId && <div className="mt-2 text-zinc-500">Path: {path.length ? path.join(' → ') : 'No connected path in current filters.'}</div>}
          </div>
        )}

        <div className="mt-5 text-[11px] leading-4 text-zinc-600">
          Graph semantics: {graph.semantics || 'current_derived_view'}. Relationships retain their stored confidence; visual focus and filtering never create or merge evidence.
        </div>
      </aside>
    </div>
  );
}
