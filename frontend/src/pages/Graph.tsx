import { useEffect, useMemo, useState } from 'react';
import {
  ReactFlow,
  Background,
  Controls,
  MiniMap,
  type Edge,
  type Node,
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import { getGraph } from '../services/api';

export function Graph({ id }: { id: number }) {
  const [g, setG] = useState<any>({ nodes: [], edges: [] });

  useEffect(() => {
    getGraph(id).then(setG);
  }, [id]);

  const nodes: Node[] = useMemo(
    () =>
      g.nodes.map((n: any, i: number) => ({
        id: n.id,
        position: {
          x: (i % 3) * 240,
          y: Math.floor(i / 3) * 150,
        },
        data: {
          label: (
            <div className="rounded-xl border border-white/10 bg-[#101010] px-4 py-3 text-xs shadow-xl">
              <div className="text-[9px] tracking-widest text-red-400">
                {n.type}
              </div>
              <div className="mt-1 max-w-44 truncate text-white">
                {n.label}
              </div>
            </div>
          ),
        },
      })),
    [g],
  );

  const edges: Edge[] = useMemo(
    () =>
      g.edges.map((e: any, i: number) => ({
        id: `e${i}`,
        source: e.source,
        target: e.target,
        label: e.relation,
        animated: false,
      })),
    [g],
  );

  return (
    <div className="h-[calc(100vh-64px)]">
      <ReactFlow nodes={nodes} edges={edges} fitView>
        <Background gap={24} />
        <MiniMap />
        <Controls />
      </ReactFlow>
    </div>
  );
}
