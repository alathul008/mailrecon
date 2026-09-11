import { useEffect, useState } from 'react';
import { Layout } from './components/Layout';
import { Dashboard } from './pages/Dashboard';
import { Lookup } from './pages/Lookup';
import { Graph } from './pages/Graph';
import { Investigations } from './pages/Investigations';
import { Investigation } from './pages/Investigation';

type Route = { page: 'Dashboard' | 'Investigations' | 'Email Lookup' | 'Investigation' | 'Graph'; id?: number };

export function parseRoute(hash: string): Route {
  const value = hash.replace(/^#\/?/, '');
  if (value === 'investigations') return { page: 'Investigations' };
  if (value === 'lookup') return { page: 'Email Lookup' };
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

  const navigate = (page: Route['page'], id?: number) => {
    const hash = page === 'Dashboard'
      ? '#/'
      : page === 'Investigations'
        ? '#/investigations'
        : page === 'Email Lookup'
          ? '#/lookup'
          : `#/${page === 'Investigation' ? 'investigation' : 'graph'}/${id}`;
    window.location.hash = hash;
  };

  let page;
  if (route.page === 'Dashboard') page = <Dashboard onLookup={() => navigate('Email Lookup')} onOpen={(id) => navigate('Investigation', id)} />;
  else if (route.page === 'Email Lookup') page = <Lookup onGraph={(id) => navigate('Graph', id)} />;
  else if (route.page === 'Investigations') page = <Investigations onOpen={(id) => navigate('Investigation', id)} onNew={() => navigate('Email Lookup')} />;
  else if (route.page === 'Investigation' && route.id !== undefined) page = <Investigation id={route.id} onBack={() => navigate('Investigations')} onOpen={(id) => navigate('Investigation', id)} />;
  else if (route.page === 'Graph' && route.id !== undefined) page = <Graph id={route.id} />;
  else page = <Dashboard onLookup={() => navigate('Email Lookup')} onOpen={(id) => navigate('Investigation', id)} />;

  return <Layout active={route.page === 'Investigation' || route.page === 'Graph' ? 'Investigations' : route.page} onNav={(x) => navigate(x as Route['page'])}>{page}</Layout>;
}
