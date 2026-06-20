import { useEffect, useRef, useState } from 'react';

const MENUS = [
  { label: 'File',    items: ['New Session', 'Import Config', '---', 'Export Logs', 'Export Loot', '---', 'Exit'] },
  { label: 'View',    items: ['Dashboard', 'Agents', 'Network Map', '---', 'Toggle Bottom Panel', 'Toggle Navigator'] },
  { label: 'Agents',  items: ['List Agents', 'Kill All Agents', '---', 'New Listener', 'Generate Payload', '---', 'Export Agent List'] },
  { label: 'Attack',  items: ['Launch Network Scan', 'Port Scan Single Target', '---', 'Credential Dump', 'Lateral Movement', '---', 'Run Script'] },
  { label: 'Payloads',items: ['Generate Payload', 'Manage Listeners', '---', 'Stage Server', 'One-liner Generator'] },
  { label: 'Scripts', items: ['Run Aggressor Script', 'Script Manager', '---', 'Load .zks File', 'Script Console'] },
  { label: 'Help',    items: ['Documentation', 'Keyboard Shortcuts', '---', 'About ZK v3.0.1'] },
];

const VIEW_MAP: Record<string, string> = {
  'Dashboard': 'dashboard', 'Agents': 'agents', 'Network Map': 'network',
  'List Agents': 'agents',  'Generate Payload': 'payloads', 'Manage Listeners': 'listeners',
};

const ACTION_MAP: Record<string, string> = {
  'Toggle Bottom Panel': 'togglebottom',
  'Kill All Agents': 'killall',
  'New Listener': 'newlistener',
};

export default function Menubar({
  onNav,
  onToggleBottom,
  onRefresh,
  onToolbarAction,
  agentStats,
}: {
  onNav?: (view: string) => void;
  onToggleBottom?: () => void;
  onRefresh?: () => void;
  onToolbarAction?: (action: string) => void;
  agentStats?: { online: number; total: number };
}) {
  const [time,    setTime]    = useState('--:--:-- UTC');
  const [open,    setOpen]    = useState<string | null>(null);
  const [newOpen, setNewOpen] = useState(false);
  const newBtnRef = useRef<HTMLButtonElement>(null);

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
    const close = () => { setOpen(null); setNewOpen(false); };
    window.addEventListener('click', close);
    return () => window.removeEventListener('click', close);
  }, []);

  const handleItem = (item: string) => {
    setOpen(null);
    if (ACTION_MAP[item]) { onToolbarAction?.(ACTION_MAP[item]); return; }
    if (VIEW_MAP[item])   { onNav?.(VIEW_MAP[item]); return; }
  };

  const act = (action: string) => onToolbarAction?.(action);

  return (
    <>
      {/* ── Menu row ── */}
      <div className="menubar" style={{ position:'relative', zIndex:2000 }}>
        <span style={{ fontSize:12, color:'var(--red-hi)', fontWeight:700, padding:'0 8px 0 4px', borderRight:'1px solid var(--b1)', marginRight:4, fontFamily:'Courier New', letterSpacing:1 }}>
          ZK
        </span>

        {MENUS.map(menu => (
          <div key={menu.label} style={{ position:'relative' }}>
            <span
              className={`menu-item${open === menu.label ? ' open' : ''}`}
              onClick={e => { e.stopPropagation(); setOpen(open === menu.label ? null : menu.label); }}
            >
              {menu.label}
            </span>
            {open === menu.label && (
              <div
                style={{ position:'absolute', top:'100%', left:0, background:'var(--panel)', border:'1px solid var(--b2)', minWidth:198, zIndex:3000, boxShadow:'0 6px 20px rgba(0,0,0,0.7)' }}
                onClick={e => e.stopPropagation()}
              >
                {menu.items.map((item, i) =>
                  item === '---'
                    ? <div key={i} style={{ height:1, background:'var(--b1)', margin:'2px 0' }} />
                    : (
                      <div
                        key={i}
                        onClick={() => handleItem(item)}
                        style={{ padding:'5px 14px', fontSize:12, color:'var(--tx1)', cursor:'pointer', whiteSpace:'nowrap' }}
                        onMouseEnter={e => { e.currentTarget.style.background = 'var(--red2)'; e.currentTarget.style.color = 'var(--red-hi)'; }}
                        onMouseLeave={e => { e.currentTarget.style.background = 'transparent'; e.currentTarget.style.color = 'var(--tx1)'; }}
                      >
                        {item}
                      </div>
                    )
                )}
              </div>
            )}
          </div>
        ))}

        <div style={{ marginLeft:'auto', display:'flex', alignItems:'center', gap:12 }}>
          <span style={{ fontSize:11, color:'var(--green)', display:'flex', alignItems:'center', gap:4 }}>
            <span style={{ width:6, height:6, borderRadius:'50%', background:'var(--green)', display:'inline-block' }} />
            C2
          </span>
          <span style={{ fontSize:11, color:'var(--tx2)', fontFamily:'Courier New' }}>{time}</span>
          <span style={{ fontSize:11, color:'var(--tx1)', fontWeight:700, paddingRight:4 }}>ROOT_ADMIN</span>
        </div>
      </div>

      {/* ── Toolbar row ── */}
      <div className="ide-toolbar">

        {/* Left group: data actions */}
        <button className="ide-tbtn" title="Refresh agent data" onClick={() => onRefresh?.()}>
          <span className="ide-tbtn-icon">⟳</span>
          <span>Refresh</span>
        </button>

        <div className="ide-toolbar-sep" />

        {/* Command palette */}
        <button className="ide-tbtn" title="Command palette (Ctrl+K)" onClick={() => act('cmdpalette')}>
          <span className="ide-tbtn-icon" style={{ fontSize:11 }}>⌨</span>
          <span>Cmd</span>
          <span style={{ fontSize:9, color:'var(--tx3)', border:'1px solid var(--b2)', padding:'0 3px', marginLeft:2 }}>⌘K</span>
        </button>

        <div className="ide-toolbar-sep" />

        {/* New — dropdown */}
        <div style={{ position:'relative' }}>
          <button
            ref={newBtnRef}
            className={`ide-tbtn${newOpen?' active':''}`}
            title="New resource"
            onClick={e => { e.stopPropagation(); setNewOpen(o => !o); }}
          >
            <span className="ide-tbtn-icon">⊕</span>
            <span>New</span>
            <span style={{ fontSize:8, marginLeft:2, color:'var(--tx3)' }}>▾</span>
          </button>
          {newOpen && (
            <div
              style={{ position:'absolute', top:'calc(100% + 2px)', left:0, background:'var(--panel)', border:'1px solid var(--b2)', minWidth:160, zIndex:3000, boxShadow:'0 6px 20px rgba(0,0,0,0.7)' }}
              onClick={e => { e.stopPropagation(); setNewOpen(false); }}
            >
              {[
                { icon:'⋮', label:'New Listener', action:'newlistener' },
                { icon:'⊕', label:'Gen Payload',  action:'newpayload'  },
              ].map(item => (
                <div
                  key={item.action}
                  onClick={() => act(item.action)}
                  style={{ display:'flex', alignItems:'center', gap:8, padding:'6px 12px', fontSize:12, color:'var(--tx1)', cursor:'pointer' }}
                  onMouseEnter={e => { e.currentTarget.style.background='var(--red2)'; e.currentTarget.style.color='var(--red-hi)'; }}
                  onMouseLeave={e => { e.currentTarget.style.background='transparent'; e.currentTarget.style.color='var(--tx1)'; }}
                >
                  <span style={{ color:'var(--tx3)', fontSize:11 }}>{item.icon}</span>
                  {item.label}
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Kill All — danger */}
        <button
          className="ide-tbtn"
          title="Kill all agents"
          onClick={() => act('killall')}
          style={{ color:'var(--red-hi)' }}
          onMouseEnter={e => { e.currentTarget.style.background='var(--red2)'; e.currentTarget.style.borderColor='var(--red)'; }}
          onMouseLeave={e => { e.currentTarget.style.background='transparent'; e.currentTarget.style.borderColor='transparent'; }}
        >
          <span className="ide-tbtn-icon">⊘</span>
          <span>Kill All</span>
        </button>

        <div className="ide-toolbar-sep" />

        {/* Live agent count */}
        <div style={{ display:'flex', alignItems:'center', gap:6, padding:'0 8px', fontSize:11, userSelect:'none' }}>
          <span style={{ width:6, height:6, borderRadius:'50%', background: (agentStats?.online ?? 0) > 0 ? 'var(--green)' : 'var(--tx3)', display:'inline-block', boxShadow:(agentStats?.online ?? 0) > 0 ? '0 0 4px var(--green)' : 'none' }} />
          <span style={{ color:'var(--tx1)' }}>
            <span style={{ color:(agentStats?.online ?? 0) > 0 ? 'var(--green)' : 'var(--tx2)', fontWeight:600 }}>{agentStats?.online ?? 0}</span>
            <span style={{ color:'var(--tx3)' }}>/{agentStats?.total ?? 0}</span>
          </span>
          <span style={{ color:'var(--tx3)', fontSize:9 }}>agents</span>
        </div>

        {/* Right: panel toggle + search */}
        <div style={{ marginLeft:'auto', display:'flex', alignItems:'center', gap:4 }}>
          <button
            className="ide-tbtn"
            title="Toggle bottom panel"
            onClick={() => onToggleBottom?.()}
          >
            <span className="ide-tbtn-icon">⊟</span>
            <span>Panel</span>
          </button>
          <div className="ide-toolbar-sep" />
          <input
            placeholder="Search…  ⌘K"
            style={{ background:'var(--inset)', border:'1px solid var(--b2)', color:'var(--tx1)', fontSize:11, padding:'2px 8px', width:150, outline:'none', height:18, fontFamily:'inherit', cursor:'pointer' }}
            onFocus={e => { e.currentTarget.style.borderColor = 'var(--red)'; e.currentTarget.blur(); onToolbarAction?.('cmdpalette'); }}
            readOnly
          />
        </div>
      </div>
    </>
  );
}
