import { useState, useEffect } from 'react';

type Section = {
  key: string;
  label: string;
  items: { key: string; icon: string; label: string; badge?: string; badgeAlert?: boolean }[];
};

const SECTIONS: Section[] = [
  { key: 'c2', label: 'C2 Operations', items: [
    { key: 'dashboard',  icon: '⊞', label: 'Dashboard' },
    { key: 'agents',     icon: '⬡', label: 'Agents',       badge: '6' },
    { key: 'shell',      icon: '$', label: 'C2 Shell' },
    { key: 'listeners',  icon: '⋮', label: 'Listeners',    badge: '2' },
    { key: 'payloads',   icon: '⊕', label: 'Payloads' },
    { key: 'sweep',      icon: '⌖', label: 'Sweep',        badge: '!', badgeAlert: true },
    { key: 'timeline',   icon: '⊢', label: 'Timeline' },
  ]},
  { key: 'net', label: 'Network & Recon', items: [
    { key: 'network',    icon: '⬡', label: 'Network Map' },
  ]},
  { key: 'intel', label: 'Intelligence', items: [
    { key: 'loot',       icon: '≡', label: 'Loot' },
    { key: 'credentials',icon: '⊛', label: 'Credentials' },
    { key: 'clipboard',  icon: '⊡', label: 'Clipboard' },
    { key: 'reports',    icon: '⊟', label: 'Reports' },
  ]},
  { key: 'arsenal', label: 'Arsenal', items: [
    { key: 'implants',   icon: '⚡', label: 'Implants' },
    { key: 'exploits',   icon: '!', label: 'Exploits' },
    { key: 'arsenal',    icon: '⚙', label: 'Build Manager' },
  ]},
  { key: 'ops', label: 'Operations', items: [
    { key: 'operations', icon: '◈', label: 'Op Planner' },
    { key: 'mitre',      icon: 'M', label: 'MITRE ATT&CK' },
    { key: 'playbooks',  icon: '▷', label: 'Playbooks' },
  ]},
  { key: 'post', label: 'Post-Exploitation', items: [
    { key: 'files',      icon: '/', label: 'File Manager' },
    { key: 'processes',  icon: '%', label: 'Processes' },
    { key: 'tunnels',    icon: '⇄', label: 'Tunnels' },
  ]},
  { key: 'opsec', label: 'OPSEC', items: [
    { key: 'opsec',      icon: '⊘', label: 'IOC Tracker' },
    { key: 'logs',       icon: '≈', label: 'Event Log' },
  ]},
  { key: 'sys', label: 'System', items: [
    { key: 'users',      icon: '⊹', label: 'Users' },
    { key: 'settings',   icon: '⚙', label: 'Settings' },
  ]},
];

export default function Sidebar({
  active,
  onNav,
  width = 220,
}: {
  active: string;
  onNav: (k: string) => void;
  width?: number;
}) {
  const [expanded, setExpanded] = useState<Set<string>>(new Set(['c2', 'net', 'intel']));
  const [filter,   setFilter]   = useState('');

  /* Auto-expand section containing the active item */
  useEffect(() => {
    const sec = SECTIONS.find(s => s.items.some(i => i.key === active));
    if (sec) setExpanded(prev => prev.has(sec.key) ? prev : new Set([...prev, sec.key]));
  }, [active]);

  const toggle = (key: string) => {
    setExpanded(prev => {
      const next = new Set(prev);
      next.has(key) ? next.delete(key) : next.add(key);
      return next;
    });
  };

  const filterLow = filter.toLowerCase();
  const filtered  = filterLow
    ? SECTIONS.map(s => ({ ...s, items: s.items.filter(i => i.label.toLowerCase().includes(filterLow)) })).filter(s => s.items.length > 0)
    : SECTIONS;

  return (
    <div className="navigator" style={{ width, minWidth: width, maxWidth: width }}>

      {/* DBeaver-style panel tab strip */}
      <div style={{ height:22, background:'var(--panel2)', borderBottom:'1px solid var(--b1)', display:'flex', alignItems:'stretch', flexShrink:0, userSelect:'none' }}>
        <div style={{ display:'flex', alignItems:'center', gap:5, padding:'0 10px', fontSize:11, color:'var(--tx0)', borderRight:'1px solid var(--b1)', borderTop:'2px solid var(--red)', background:'var(--panel)', flexShrink:0 }}>
          <span style={{ color:'var(--red)', fontSize:9 }}>⬡</span>
          <span>Navigator</span>
        </div>
        <div style={{ marginLeft:'auto', display:'flex', alignItems:'center', paddingRight:4, gap:0 }}>
          <span
            title="Collapse all"
            onClick={() => setExpanded(new Set())}
            style={{ width:18, height:18, display:'flex', alignItems:'center', justifyContent:'center', fontSize:11, color:'var(--tx3)', cursor:'pointer' }}
            onMouseEnter={e => (e.currentTarget.style.color = 'var(--tx1)')}
            onMouseLeave={e => (e.currentTarget.style.color = 'var(--tx3)')}
          >⊟</span>
          <span
            title="Expand all"
            onClick={() => setExpanded(new Set(SECTIONS.map(s => s.key)))}
            style={{ width:18, height:18, display:'flex', alignItems:'center', justifyContent:'center', fontSize:11, color:'var(--tx3)', cursor:'pointer' }}
            onMouseEnter={e => (e.currentTarget.style.color = 'var(--tx1)')}
            onMouseLeave={e => (e.currentTarget.style.color = 'var(--tx3)')}
          >⊞</span>
        </div>
      </div>

      {/* Filter */}
      <div className="navigator-search">
        <input
          value={filter}
          onChange={e => setFilter(e.target.value)}
          placeholder="Filter views..."
        />
      </div>

      {/* Tree */}
      <div style={{ flex:1, overflowY:'auto' }}>
        {filtered.map(sec => (
          <div key={sec.key} className="tree-section">
            <div className="tree-section-hdr" onClick={() => toggle(sec.key)}>
              <span className="tree-arrow">{expanded.has(sec.key) ? '▾' : '▸'}</span>
              <span style={{ flex:1 }}>{sec.label}</span>
              <span style={{ fontSize:9, color:'var(--tx3)', paddingRight:2 }}>{sec.items.length}</span>
            </div>

            {expanded.has(sec.key) && sec.items.map(item => (
              <div
                key={item.key}
                className={`tree-item${active === item.key ? ' active' : ''}`}
                onClick={() => onNav(item.key)}
              >
                <span className="tree-item-icon">{item.icon}</span>
                <span className="tree-item-label">{item.label}</span>
                {item.badge && (
                  <span className={`tree-badge${item.badgeAlert ? ' alert' : ''}`}>{item.badge}</span>
                )}
              </div>
            ))}
          </div>
        ))}
      </div>
    </div>
  );
}
