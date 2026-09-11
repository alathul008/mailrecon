import { useEffect, useState } from 'react';
import { Layout } from './components/Layout';
import { Dashboard } from './pages/Dashboard';
import { Lookup } from './pages/Lookup';
import { Graph } from './pages/Graph';
import { Investigations } from './pages/Investigations';
import { Investigation } from './pages/Investigation';
import { Comparison } from './pages/Comparison';

type Route = { page: 'Dashboard' | 'Investigations' | 'Email Lookup' | 'Investigation' | 'Graph' | 'Comparison'; id?: number; left?: number; right?: number };

export function parseRoute(hash: string): Route {
  const value = hash.replace(/^#\/?/, '');
  if (value === 'investigations') return { page: 'Investigations' };
  if (value === 'lookup') return { page: 'Email Lookup' };
  const compare = value.match(/^compare\/(\d+)\/(\d+)$/);
  if (compare) return { page: 'Comparison', left: Number(compare[1]), right: Number(compare[2]) };
  if (value === 'compare') return { page: 'Comparison' };
  const match = value.match(/^(investigation|graph)\/(\d+)$/);
  if (match) return { page: match[1] === 'investigation' ? 'Investigation' : 'Graph', id: Number(match[2]) };
  return { page: 'Dashboard' };
}

export default function App() {
  const initial = parseRoute(window.location.hash);
  const [route, setRoute] = useState<Route>(initial);

  useEffect(() => {
    const onHashChange = () => setRoute(parseRoute(window.location.hash));
    window.addEventListener('hashchange', onHashChange);
    return () => window.removeEventListener('hashchange', onHashChange);
  }, []);

  const navigate = (page: Route['page'], id?: number, left?: number, right?: number) => {
    const hash = page === 'Dashboard' ? '#/' : page === 'Investigations' ? '#/investigations' : page === 'Email Lookup' ? '#/lookup' : page === 'Comparison' ? (left && right ? `#/compare/${left}/${right}` : '#/compare') : `#/${page === 'Investigation' ? 'investigation' : 'graph'}/${id}`;
    window.location.hash = hash;
  };

  let page;
  if (route.page === 'Dashboard') page = <Dashboard onLookup={() => navigate('Email Lookup')} onOpen={(id) => navigate('Investigation', id)} />;
  else if (route.page === 'Email Lookup') page = <Lookup onGraph={(id) => navigate('Graph', id)} />;
  else if (route.page === 'Investigations') page = <Investigations onOpen={(id) => navigate('Investigation', id)} onNew={() => navigate('Email Lookup')} onCompare={() => navigate('Comparison')} />;
  else if (route.page === 'Investigation' && route.id !== undefined) page = <Investigation id={route.id} onBack={() => navigate('Investigations')} onOpen={(id) => navigate('Investigation', id)} />;
  else if (route.page === 'Graph' && route.id !== undefined) page = <Graph id={route.id} />;
  else if (route.page === 'Comparison') page = <Comparison onBack={() => navigate('Investigations')} initialLeft={route.left} initialRight={route.right} />;
  else page = <Dashboard onLookup={() => navigate('Email Lookup')} onOpen={(id) => navigate('Investigation', id)} />;

  return <Layout active={route.page === 'Investigation' || route.page === 'Graph' || route.page === 'Comparison' ? 'Investigations' : route.page} onNav={(x) => navigate(x as Route['page'])}>{page}</Layout>;
}
