import { Activity, FolderSearch, LayoutDashboard, Menu, Search, ShieldCheck, X } from 'lucide-react';

const items = [
  ['Dashboard', LayoutDashboard],
  ['Investigations', FolderSearch],
  ['Email Lookup', Search],
] as const;

export function Layout({ children, active, onNav }: { children: React.ReactNode; active: string; onNav: (x: string) => void }) {
  const [mobileOpen, setMobileOpen] = React.useState(false);
  const navigate = (label: string) => {
    onNav(label);
    setMobileOpen(false);
  };

  return <div className="min-h-screen text-zinc-100">
    <aside className="fixed inset-y-0 left-0 hidden w-64 border-r border-white/8 bg-[#0b0b0b]/95 p-4 lg:block">
      <div className="mb-8 flex items-center gap-3 px-2">
        <div className="grid h-10 w-10 place-items-center rounded-xl bg-red-500/15 text-red-400"><ShieldCheck size={21}/></div>
        <div><div className="font-bold tracking-tight">MailRecon</div><div className="text-[10px] uppercase tracking-[.2em] text-zinc-500">Email Intelligence</div></div>
      </div>
      <nav aria-label="Primary navigation" className="space-y-1">
        {items.map(([label, Icon]) => <button key={label} onClick={() => navigate(label)} className={`flex w-full items-center gap-3 rounded-xl px-3 py-2.5 text-sm transition ${active === label ? 'bg-white/7 text-white' : 'text-zinc-400 hover:bg-white/5 hover:text-white'}`}><Icon size={17}/>{label}</button>)}
      </nav>
      <div className="absolute bottom-4 left-4 right-4 rounded-xl border border-emerald-500/15 bg-emerald-500/5 p-3"><div className="flex items-center gap-2 text-xs text-emerald-300"><Activity size={13}/>Local-first mode</div><p className="mt-1 text-[11px] leading-4 text-zinc-500">No telemetry. External calls only through enabled providers.</p></div>
    </aside>
    <main className="lg:pl-64">
      <header className="sticky top-0 z-20 flex h-16 items-center justify-between border-b border-white/8 bg-[#070707]/80 px-5 backdrop-blur-xl lg:px-8">
        <div className="flex items-center gap-3">
          <button aria-label="Open navigation" aria-expanded={mobileOpen} onClick={() => setMobileOpen(true)} className="rounded-lg p-2 text-zinc-400 hover:bg-white/5 hover:text-white lg:hidden"><Menu size={19}/></button>
          <span className="text-sm text-zinc-400">{active}</span>
        </div>
        <div className="flex items-center gap-2 text-xs text-zinc-500"><span className="h-2 w-2 rounded-full bg-emerald-400"/> System ready</div>
      </header>
      {mobileOpen && <div className="fixed inset-0 z-40 lg:hidden"><button aria-label="Close navigation overlay" className="absolute inset-0 bg-black/70" onClick={() => setMobileOpen(false)}/><aside aria-label="Mobile navigation" className="absolute inset-y-0 left-0 w-72 border-r border-white/8 bg-[#0b0b0b] p-4 shadow-2xl"><div className="mb-8 flex items-center justify-between"><div className="flex items-center gap-3"><div className="grid h-9 w-9 place-items-center rounded-xl bg-red-500/15 text-red-400"><ShieldCheck size={19}/></div><div className="font-bold">MailRecon</div></div><button aria-label="Close navigation" onClick={() => setMobileOpen(false)} className="rounded-lg p-2 text-zinc-400 hover:bg-white/5 hover:text-white"><X size={18}/></button></div><nav aria-label="Mobile primary navigation" className="space-y-1">{items.map(([label, Icon]) => <button key={label} onClick={() => navigate(label)} className={`flex w-full items-center gap-3 rounded-xl px-3 py-3 text-sm ${active === label ? 'bg-white/7 text-white' : 'text-zinc-400 hover:bg-white/5 hover:text-white'}`}><Icon size={17}/>{label}</button>)}</nav></aside></div>}
      {children}
    </main>
  </div>;
}
