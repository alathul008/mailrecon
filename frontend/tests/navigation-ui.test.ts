import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('react', async () => {
  const actual = await vi.importActual<typeof import('react')>('react');
  let state: unknown[] = [];
  let cursor = 0;
  const effects = new Set<number>();
  return {
    ...actual,
    useState: <T,>(initial: T) => {
      const i = cursor++;
      if (!(i in state)) state[i] = initial;
      return [state[i], (next: T | ((value: T) => T)) => { state[i] = typeof next === 'function' ? (next as (value: T) => T)(state[i] as T) : next; }] as const;
    },
    useEffect: (fn: () => void | (() => void)) => {
      const i = cursor++;
      if (!effects.has(i)) { effects.add(i); void fn(); }
    },
    __reset: () => { state = []; cursor = 0; effects.clear(); },
    __rewind: () => { cursor = 0; },
  };
});

function text(node: any): string {
  if (node == null || typeof node === 'boolean') return '';
  if (typeof node === 'string' || typeof node === 'number') return String(node);
  if (Array.isArray(node)) return node.map(text).join('');
  return text(node.props?.children);
}

function elements(node: any): any[] {
  if (node == null || typeof node !== 'object') return [];
  if (Array.isArray(node)) return node.flatMap(elements);
  return [node, ...elements(node.props?.children)];
}

function installWindow() {
  const listeners = new Map<string, Set<() => void>>();
  (globalThis as any).window = {
    location: { hash: '' },
    addEventListener: (name: string, fn: () => void) => { if (!listeners.has(name)) listeners.set(name, new Set()); listeners.get(name)!.add(fn); },
    removeEventListener: (name: string, fn: () => void) => listeners.get(name)?.delete(fn),
  };
}

beforeEach(async () => {
  installWindow();
  (await import('react') as any).__reset();
});

describe('Phase 21 navigation integrity', () => {
  it('maps supported hash routes and safely falls back for invalid routes', async () => {
    const { parseRoute } = await import('../src/App');
    expect(parseRoute('#/')).toEqual({ page: 'Dashboard' });
    expect(parseRoute('#/investigations')).toEqual({ page: 'Investigations' });
    expect(parseRoute('#/lookup')).toEqual({ page: 'Email Lookup' });
    expect(parseRoute('#/investigation/42')).toEqual({ page: 'Investigation', id: 42 });
    expect(parseRoute('#/graph/42')).toEqual({ page: 'Graph', id: 42 });
    expect(parseRoute('#/unknown')).toEqual({ page: 'Dashboard' });
    expect(parseRoute('#/investigation/not-an-id')).toEqual({ page: 'Dashboard' });
  });

  it('renders only implemented primary navigation and opens/closes mobile navigation', async () => {
    const { Layout } = await import('../src/components/Layout');
    const r = await import('react') as any;
    const onNav = vi.fn();
    r.__rewind();
    let tree = Layout({ active: 'Dashboard', onNav, children: 'content' });
    expect(text(tree)).toContain('Dashboard');
    expect(text(tree)).toContain('Investigations');
    expect(text(tree)).toContain('Email Lookup');
    expect(text(tree)).not.toContain('Domains');
    expect(text(tree)).not.toContain('Breaches');
    expect(text(tree)).not.toContain('Settings');
    const open = elements(tree).find((e) => e.type === 'button' && e.props['aria-label'] === 'Open navigation');
    open.props.onClick();
    r.__rewind();
    tree = Layout({ active: 'Dashboard', onNav, children: 'content' });
    expect(text(tree)).toContain('Mobile primary navigation');
    const mobileInvestigation = elements(tree).find((e) => e.type === 'button' && text(e) === 'Investigations');
    mobileInvestigation.props.onClick();
    expect(onNav).toHaveBeenCalledWith('Investigations');
  });
});
