import { useEffect, useState } from 'react';

// Menubar with real functional items and no duplicates
const MENUS = [
  {
    label: 'File',
    items: ['New Session', 'Import Config', '---', 'Export Logs', 'Export Loot', '---', 'Exit'],
  },
  {
    label: 'View',
    items: ['Dashboard', 'Agents', 'Network Map', '---', 'Toggle Event Viewer', 'Toggle Status Bar'],
  },
  {
    label: 'Agents',
    items: ['List Agents', 'Kill All Agents', '---', 'New Listener', 'Generate Payload', '---', 'Export Agent List'],
  },
  {
    label: 'Attack',
    items: ['Launch Network Scan', 'Port Scan Single Target', '---', 'Credential Dump', 'Lateral Movement', '---', 'Run Script'],
  },
  {
    label: 'Payloads',
    items: ['Generate Payload', 'Manage Listeners', '---', 'Stage Server', 'One-liner Generator'],
  },
  {
    label: 'Scripts',
    items: ['Run Aggressor Script', 'Script Manager', '---', 'Load .zks File', 'Script Console'],
  },
  {
    label: 'Help',
    items: ['Documentation', 'Keyboard Shortcuts', '---', 'About ZK v3.0.1'],
  },
];

export default function Menubar() {
  const [time, setTime]       = useState('--:--:-- UTC');
  const [open, setOpen]       = useState<string | null>(null);

  useEffect(() => {
    const tick = () => {
      const n = new Date();
      setTime(`${n.getUTCHours().toString().padStart(2,'0')}:${n.getUTCMinutes().toString().padStart(2,'0')}:${n.getUTCSeconds().toString().padStart(2,'0')} UTC`);
    };
    tick();
    const id = setInterval(tick, 1000);
    return () => clearInterval(id);
  }, []);

  useEffect(() => {
    const close = () => setOpen(null);
    window.addEventListener('click', close);
    return () => window.removeEventListener('click', close);
  }, []);

  return (
    <div className="menubar" style={{ position: 'relative', zIndex: 2000 }}>
      {MENUS.map(menu => (
        <div key={menu.label} style={{ position: 'relative' }}>
          <span
            className="menu-item"
            style={{ color: open === menu.label ? '#e05c6e' : '#e8e8e8', background: open === menu.label ? '#1a0000' : 'transparent' }}
            onClick={e => { e.stopPropagation(); setOpen(open === menu.label ? null : menu.label); }}
          >
            {menu.label}
          </span>
          {open === menu.label && (
            <div style={{
              position: 'absolute', top: '100%', left: 0,
              background: '#111', border: '1px solid #2a2a2a',
              minWidth: 180, zIndex: 3000,
              boxShadow: '0 4px 20px rgba(0,0,0,0.8)',
            }}
              onClick={e => e.stopPropagation()}>
              {menu.items.map((item, i) =>
                item === '---'
                  ? <div key={i} style={{ height: 1, background: '#1e1e1e', margin: '2px 0' }} />
                  : (
                    <div key={i} onClick={() => setOpen(null)} style={{
                      padding: '6px 14px', fontSize: 12, color: '#aaaaaa',
                      fontFamily: 'Courier New', cursor: 'pointer', whiteSpace: 'nowrap',
                    }}
                      onMouseEnter={e => (e.currentTarget.style.background = '#1a0000', e.currentTarget.style.color = '#e05c6e')}
                      onMouseLeave={e => (e.currentTarget.style.background = 'transparent', e.currentTarget.style.color = '#aaaaaa')}>
                      {item}
                    </div>
                  )
              )}
            </div>
          )}
        </div>
      ))}

      <div style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: 20 }}>
        <span style={{ fontSize: 11, color: 'var(--green)', fontFamily: 'Courier New' }}>[*] C2 ONLINE</span>
        <span style={{ fontSize: 11, color: '#aaaaaa', fontFamily: 'Courier New' }}>{time}</span>
        <span style={{ fontSize: 11, color: '#e8e8e8', fontFamily: 'Courier New', fontWeight: 700 }}>ROOT_ADMIN</span>
      </div>
    </div>
  );
}
