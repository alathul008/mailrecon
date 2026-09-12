import { useEffect, useState } from 'react';
import { Layout } from './components/Layout';
import { Dashboard } from './pages/Dashboard';
import { Lookup } from './pages/Lookup';
import { Graph } from './pages/Graph';
import { Investigations } from './pages/Investigations';
import { Investigation } from './pages/Investigation';
import { Comparison } from './pages/Comparison';

type InvestigationTab = 'Overview' | 'Account Discovery' | 'Correlations' | 'Evidence' | 'Providers' | 'Timeline' | 'Graph' | 'Reports';
type Route = { page: 'Dashboard' | 'Investigations' | 'Email Lookup' | 'Investigation' | 'Graph' | 'Comparison'; id?: number; left?: number; right?: number; tab?: InvestigationTab };
const tabBySlug: Record<string, InvestigationTab> = { overview: 'Overview', 'account-discovery': 'Account Discovery', correlations: 'Correlations', evidence: 'Evidence', providers: 'Providers', timeline: 'Timeline', graph: 'Graph', reports: 'Reports' };
const slugByTab: Record<InvestigationTab, string> = Object.fromEntries(Object.entries(tabBySlug).map(([slug, tab]) => [tab, slug])) as Record<InvestigationTab, string>;

export function parseRoute(hash: string): Route {
  const value = hash.replace(/^#\/?/, '');
  if (value === 'investigations') return { page: 'Investigations' };
  if (value === 'lookup') return { page: 'Email Lookup' };
  const compare = value.match(/^compare\/(\d+)\/(\d+)$/); if (compare) return { page: 'Comparison', left: Number(compare[1]), right: Number(compare[2]) };
  if (value === 'compare') return { page: 'Comparison' };
  const match = value.match(/^(investigation|graph)\/(\d+)(?:\/([a-z-]+))?$/);
  if (match) { if (match[1] === 'graph') return { page: 'Graph', id: Number(match[2]) }; const tab = match[3] ? tabBySlug[match[3]] : undefined; if (match[3] && !tab) return { page: 'Dashboard' }; return { page: 'Investigation', id: Number(match[2]), tab }; }
  return { page: 'Dashboard' };
}

export default function App() {
  const initial = parseRoute(window.location.hash); const [route, setRoute] = useState<Route>(initial);
  useEffect(() => { const onHashChange = () => setRoute(parseRoute(window.location.hash)); window.addEventListener('hashchange', onHashChange); return () => window.removeEventListener('hashchange', onHashChange); }, []);
  const navigate = (page: Route['page'], id?: number, left?: number, right?: number, tab?: InvestigationTab) => { const hash = page === 'Dashboard' ? '#/' : page === 'Investigations' ? '#/investigations' : page === 'Email Lookup' ? '#/lookup' : page === 'Comparison' ? (left && right ? `#/compare/${left}/${right}` : '#/compare') : `#/${page === 'Investigation' ? 'investigation' : 'graph'}/${id}${page === 'Investigation' && tab && tab !== 'Overview' ? `/${slugByTab[tab]}` : ''}`; window.location.hash = hash; };
  let page;
  if (route.page === 'Dashboard') page = <Dashboard onLookup={() => navigate('Email Lookup')} onOpen={(id) => navigate('Investigation', id)} />;
  else if (route.page === 'Email Lookup') page = <Lookup onGraph={(id) => navigate('Graph', id)} />;
  else if (route.page === 'Investigations') page = <Investigations onOpen={(id) => navigate('Investigation', id)} onNew={() => navigate('Email Lookup')} onCompare={() => navigate('Comparison')} />;
  else if (route.page === 'Investigation' && route.id !== undefined) page = <Investigation id={route.id} initialTab={route.tab} onBack={() => navigate('Investigations')} onOpen={(id) => navigate('Investigation', id)} onTab={(tab) => navigate('Investigation', route.id, undefined, undefined, tab)} />;
  else if (route.page === 'Graph' && route.id !== undefined) page = <Graph id={route.id} />;
  else if (route.page === 'Comparison') page = <Comparison onBack={() => navigate('Investigations')} initialLeft={route.left} initialRight={route.right} />;
  else page = <Dashboard onLookup={() => navigate('Email Lookup')} onOpen={(id) => navigate('Investigation', id)} />;
  return <Layout active={route.page === 'Investigation' || route.page === 'Graph' || route.page === 'Comparison' ? 'Investigations' : route.page} onNav={(x) => navigate(x as Route['page'])}>{page}</Layout>;
}
