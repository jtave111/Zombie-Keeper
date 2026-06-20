import { useState, useEffect, useRef, useCallback, lazy, Suspense } from 'react';
import Menubar from '@/components/layout/Menubar';
import Sidebar from '@/components/layout/Sidebar';
import AgentsView from '@/components/agents/AgentsView';
import AgentShell from '@/components/agents/AgentShell';
import ProcessesView from '@/components/agents/ProcessesView';
import NetworkView from '@/components/network/NetworkView';
import SettingsView from '@/components/shared/SettingsView';
import ShellModule from '@/components/shell/ShellModule';
import PayloadGenerator from '@/components/payloads/PayloadGenerator';
import ListenersView from '@/components/listeners/ListenersView';
import CredentialsView from '@/components/intelligence/CredentialsView';
import LootView from '@/components/intelligence/LootView';
import ReportsView from '@/components/intelligence/ReportsView';
import UsersView from '@/components/users/UsersView';
import SweepView from '@/components/operations/SweepView';
import MitreView from '@/components/operations/MitreView';
import OperationsView from '@/components/operations/OperationsView';
import FileManagerView from '@/components/arsenal/FileManagerView';
import TunnelsView from '@/components/arsenal/TunnelsView';
import PlaybooksView from '@/components/arsenal/PlaybooksView';
import ArsenalView from '@/components/arsenal/ArsenalView';
import ImplantsView from '@/components/arsenal/ImplantsView';
import ExploitsView from '@/components/arsenal/ExploitsView';
import OpsecView from '@/components/opsec/OpsecView';
import TimelineView from '@/components/c2/TimelineView';
import ClipboardView from '@/components/c2/ClipboardView';
import { Agent, FeedEvent } from '@/lib/models/agents/agentModel';
import { agentsApi, toAgent, mapStatus } from '@/lib/client/api';

const DashboardView = lazy(() => import('@/components/dashboard/DashboardView'));

type View =
  'dashboard'|'agents'|'shell'|'payloads'|'network'|'logs'|'settings'|
  'listeners'|'credentials'|'loot'|'reports'|'users'|
  'sweep'|'operations'|'mitre'|'playbooks'|
  'files'|'processes'|'tunnels'|
  'implants'|'exploits'|'arsenal'|'opsec'|
  'timeline'|'clipboard';

const VIEW_LABELS: Record<View, string> = {
  dashboard:'Dashboard',   agents:'Agents',        shell:'C2 Shell',
  payloads:'Payloads',     network:'Network Map',  logs:'Event Log',
  settings:'Settings',     listeners:'Listeners',  credentials:'Credentials',
  loot:'Loot',             reports:'Reports',      users:'Users',
  sweep:'Sweep',           operations:'Op Planner',mitre:'MITRE ATT&CK',
  playbooks:'Playbooks',   files:'File Manager',   processes:'Processes',
  tunnels:'Tunnels',       implants:'Implants',    exploits:'Exploits',
  arsenal:'Arsenal Build', opsec:'IOC Tracker',
  timeline:'Timeline',     clipboard:'Clipboard',
};

const VIEW_ICONS: Record<View, string> = {
  dashboard:'⊞', agents:'⬡',  shell:'$',  payloads:'⊕', network:'⬡',
  logs:'≈',      settings:'⚙', listeners:'⋮', credentials:'⊛', loot:'≡',
  reports:'⊟',   users:'⊹',   sweep:'⌖',  operations:'◈', mitre:'M',
  playbooks:'▷', files:'/',    processes:'%', tunnels:'⇄',    implants:'⚡',
  exploits:'!',  arsenal:'⚙', opsec:'⊘',
  timeline:'⊢',  clipboard:'⊡',
};

const FEED_CLS: Record<string, string> = { ok:'t-ok', err:'t-err', warn:'t-warn', sys:'t-sys' };
const FEED_ICO: Record<string, string> = { ok:'[+]', err:'[-]', warn:'[!]', sys:'[*]' };

function buildFeed(agents: Agent[]): FeedEvent[] {
  return agents.map(a => {
    const now  = new Date();
    const time = [now.getUTCHours(), now.getUTCMinutes(), now.getUTCSeconds()]
      .map(n => String(n).padStart(2, '0')).join(':');
    if (a.status === 'ONLINE')
      return { type:'ok'   as const, msg:`${a.id} connected — ${a.hostname} (${a.priv})`, time };
    if (a.status === 'LOST')
      return { type:'err'  as const, msg:`${a.id} LOST — ${a.hostname} timeout`, time };
    return   { type:'warn' as const, msg:`${a.id} idle — ${a.hostname}`, time };
  });
}

// ── Modal shell ──────────────────────────────────────────────────────────────

function Modal({ title, width = 400, onClose, children, footer }: {
  title: React.ReactNode; width?: number; onClose: () => void;
  children: React.ReactNode; footer?: React.ReactNode;
}) {
  return (
    <div
      onClick={onClose}
      style={{ position:'fixed', inset:0, zIndex:9000, background:'rgba(0,0,0,0.65)', display:'flex', alignItems:'center', justifyContent:'center' }}
    >
      <div
        onClick={e => e.stopPropagation()}
        style={{ width, background:'var(--panel)', border:'1px solid var(--b3)', boxShadow:'0 20px 60px rgba(0,0,0,0.85)' }}
      >
        <div style={{ padding:'9px 14px', borderBottom:'1px solid var(--b1)', display:'flex', alignItems:'center', justifyContent:'space-between' }}>
          <span style={{ fontSize:12, color:'var(--tx0)', fontWeight:700 }}>{title}</span>
          <span style={{ fontSize:16, color:'var(--tx3)', cursor:'pointer', padding:'0 4px', lineHeight:1 }} onClick={onClose}>×</span>
        </div>
        <div style={{ padding:'14px 16px' }}>{children}</div>
        {footer && (
          <div style={{ padding:'10px 16px', borderTop:'1px solid var(--b1)', display:'flex', gap:8, justifyContent:'flex-end' }}>
            {footer}
          </div>
        )}
      </div>
    </div>
  );
}

function FieldRow({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div style={{ display:'flex', flexDirection:'column', gap:3 }}>
      <label style={{ fontSize:10, color:'var(--tx3)', textTransform:'uppercase', letterSpacing:0.6 }}>{label}</label>
      {children}
    </div>
  );
}

function NewListenerModal({ onClose }: { onClose: () => void }) {
  const [proto, setProto] = useState('TCP');
  const [port,  setPort]  = useState('4444');
  const [host,  setHost]  = useState('0.0.0.0');
  const [name,  setName]  = useState('');
  return (
    <Modal title="⊕ New Listener" onClose={onClose} footer={
      <>
        <button className="zk-btn" onClick={onClose}>Cancel</button>
        <button className="zk-btn primary" onClick={onClose}>Add {proto}/{host}:{port}</button>
      </>
    }>
      <div style={{ display:'flex', flexDirection:'column', gap:10 }}>
        <FieldRow label="Name">
          <input className="zk-input" value={name} onChange={e=>setName(e.target.value)} placeholder="listener_01" />
        </FieldRow>
        <div style={{ display:'flex', gap:8 }}>
          <FieldRow label="Protocol">
            <select className="zk-select" value={proto} onChange={e=>setProto(e.target.value)}>
              <option>TCP</option><option>HTTP</option><option>HTTPS</option><option>DNS</option>
            </select>
          </FieldRow>
          <FieldRow label="Port">
            <input className="zk-input" value={port} onChange={e=>setPort(e.target.value)} style={{ width:80 }} />
          </FieldRow>
          <FieldRow label="Bind Address">
            <input className="zk-input" value={host} onChange={e=>setHost(e.target.value)} />
          </FieldRow>
        </div>
      </div>
    </Modal>
  );
}

function NewPayloadModal({ onClose }: { onClose: () => void }) {
  const [type, setType] = useState('EXE');
  const [os,   setOs]   = useState('Windows');
  const [arch, setArch] = useState('x64');
  const [url,  setUrl]  = useState('http://C2_IP:4444');
  const [enc,  setEnc]  = useState('XOR');
  return (
    <Modal title="⊕ Generate Payload" width={440} onClose={onClose} footer={
      <>
        <button className="zk-btn" onClick={onClose}>Cancel</button>
        <button className="zk-btn primary" onClick={onClose}>Generate Payload</button>
      </>
    }>
      <div style={{ display:'flex', flexDirection:'column', gap:10 }}>
        <div style={{ display:'flex', gap:8 }}>
          <FieldRow label="Type">
            <select className="zk-select" value={type} onChange={e=>setType(e.target.value)}>
              <option>EXE</option><option>DLL</option><option>Shellcode</option>
              <option>PowerShell</option><option>Python</option><option>Bash</option>
            </select>
          </FieldRow>
          <FieldRow label="OS">
            <select className="zk-select" value={os} onChange={e=>setOs(e.target.value)}>
              <option>Windows</option><option>Linux</option><option>macOS</option>
            </select>
          </FieldRow>
          <FieldRow label="Arch">
            <select className="zk-select" value={arch} onChange={e=>setArch(e.target.value)}>
              <option>x64</option><option>x86</option><option>ARM64</option>
            </select>
          </FieldRow>
        </div>
        <FieldRow label="C2 Callback URL">
          <input className="zk-input" value={url} onChange={e=>setUrl(e.target.value)} />
        </FieldRow>
        <FieldRow label="Encoding">
          <select className="zk-select" value={enc} onChange={e=>setEnc(e.target.value)}>
            <option>XOR</option><option>Base64</option><option>RC4</option><option>None</option>
          </select>
        </FieldRow>
        <div style={{ background:'var(--inset2)', border:'1px solid var(--b2)', padding:'8px 10px', fontSize:10, color:'var(--tx3)', fontFamily:'Courier New', lineHeight:1.6 }}>
          [*] Output: zombie_{type.toLowerCase()}_{os.toLowerCase()}_{arch}.bin<br/>
          [*] Callback: {url}<br/>
          [*] Encoding: {enc}
        </div>
      </div>
    </Modal>
  );
}

// ── Command palette data ─────────────────────────────────────────────────────

type CmdEntry = { label: string; icon: string; view?: View; action?: string; cat: string };

const CMD_VIEWS: CmdEntry[] = (Object.entries(VIEW_LABELS) as [View, string][]).map(([k, label]) => ({
  label, icon: VIEW_ICONS[k], view: k, cat: 'View',
}));

const CMD_ACTIONS: CmdEntry[] = [
  { label:'Refresh Data',        icon:'⟳', action:'refresh',       cat:'Action' },
  { label:'New Listener',        icon:'⊕', action:'newlistener',   cat:'Action' },
  { label:'Generate Payload',    icon:'⊕', action:'newpayload',    cat:'Action' },
  { label:'Kill All Agents',     icon:'⊘', action:'killall',       cat:'Action' },
  { label:'Toggle Bottom Panel', icon:'⊟', action:'togglebottom',  cat:'UI'     },
  { label:'Close Active Tab',    icon:'×', action:'closetab',      cat:'UI'     },
];

const ALL_CMDS: CmdEntry[] = [...CMD_VIEWS, ...CMD_ACTIONS];

// ── Main component ───────────────────────────────────────────────────────────

export default function App() {
  const [openTabs,       setOpenTabs]       = useState<View[]>(['dashboard']);
  const [activeTab,      setActiveTab]      = useState<View>('dashboard');
  const [showBottom,     setShowBottom]     = useState(true);
  const [bottomTab,      setBottomTab]      = useState<'events'|'output'>('events');
  const [shellAgent,     setShellAgent]     = useState<Agent|null>(null);
  const [agentStats,     setAgentStats]     = useState({ online:0, total:0 });
  const [feed,           setFeed]           = useState<FeedEvent[]>([]);
  const [cmd,            setCmd]            = useState('');
  const [sidebarW,       setSidebarW]       = useState(220);
  const [showCmdPalette, setShowCmdPalette] = useState(false);
  const [showKillModal,  setShowKillModal]  = useState(false);
  const [showNewList,    setShowNewList]    = useState(false);
  const [showNewPay,     setShowNewPay]     = useState(false);
  const [cmdQuery,       setCmdQuery]       = useState('');

  const activeTabRef = useRef(activeTab);
  const loadRef      = useRef<() => void>(() => {});
  const dragRef      = useRef({ active:false, startX:0, startW:0 });

  activeTabRef.current = activeTab;

  const load = useCallback(() =>
    agentsApi.list()
      .then(list => {
        setAgentStats({ online: list.filter(a => mapStatus(a.status) === 'ONLINE').length, total: list.length });
        setFeed(buildFeed(list.map(toAgent)));
      })
      .catch(console.error),
  []);

  loadRef.current = load;

  useEffect(() => {
    load();
    const id = setInterval(load, 30_000);
    return () => clearInterval(id);
  }, [load]);

  /* Sidebar resize drag */
  useEffect(() => {
    const onMove = (e: MouseEvent) => {
      if (!dragRef.current.active) return;
      setSidebarW(Math.max(160, Math.min(420, dragRef.current.startW + e.clientX - dragRef.current.startX)));
    };
    const onUp = () => {
      if (!dragRef.current.active) return;
      dragRef.current.active = false;
      document.body.style.cursor = '';
      document.body.style.userSelect = '';
    };
    window.addEventListener('mousemove', onMove);
    window.addEventListener('mouseup', onUp);
    return () => { window.removeEventListener('mousemove', onMove); window.removeEventListener('mouseup', onUp); };
  }, []);

  const onResizeStart = (e: React.MouseEvent) => {
    dragRef.current = { active:true, startX:e.clientX, startW:sidebarW };
    document.body.style.cursor = 'col-resize';
    document.body.style.userSelect = 'none';
  };

  /* Keyboard shortcuts */
  useEffect(() => {
    const h = (e: KeyboardEvent) => {
      const meta = e.ctrlKey || e.metaKey;
      if (meta && e.key === 'k') { e.preventDefault(); setCmdQuery(''); setShowCmdPalette(true); }
      if (meta && e.key === 'w') {
        e.preventDefault();
        const cur = activeTabRef.current;
        setOpenTabs(prev => {
          const next = prev.filter(t => t !== cur);
          if (!next.length) { setActiveTab('dashboard'); return ['dashboard']; }
          setActiveTab(next[Math.max(0, prev.indexOf(cur) - 1)]);
          return next;
        });
      }
      if (e.key === 'Escape') {
        setShowCmdPalette(false);
        setShowKillModal(false);
        setShowNewList(false);
        setShowNewPay(false);
      }
    };
    window.addEventListener('keydown', h);
    return () => window.removeEventListener('keydown', h);
  }, []);

  const openTab = (key: string) => {
    const v = key as View;
    if (!VIEW_LABELS[v]) return;
    setOpenTabs(prev => prev.includes(v) ? prev : [...prev, v]);
    setActiveTab(v);
    if (v !== 'agents') setShellAgent(null);
  };

  const closeTab = (key: View, e: React.MouseEvent) => {
    e.stopPropagation();
    setOpenTabs(prev => {
      const next = prev.filter(t => t !== key);
      if (!next.length) { setActiveTab('dashboard'); return ['dashboard']; }
      if (activeTab === key) setActiveTab(next[Math.max(0, prev.indexOf(key) - 1)]);
      return next;
    });
  };

  const handleToolbarAction = (action: string) => {
    if (action === 'cmdpalette')   { setCmdQuery(''); setShowCmdPalette(true); }
    if (action === 'killall')      setShowKillModal(true);
    if (action === 'newlistener')  setShowNewList(true);
    if (action === 'newpayload')   setShowNewPay(true);
    if (action === 'togglebottom') setShowBottom(s => !s);
    if (action === 'refresh')      loadRef.current();
  };

  const execCmd = (c: CmdEntry) => {
    setShowCmdPalette(false);
    if (c.view)   { openTab(c.view); return; }
    if (c.action === 'closetab') {
      const cur = activeTabRef.current;
      setOpenTabs(prev => {
        const next = prev.filter(t => t !== cur);
        if (!next.length) { setActiveTab('dashboard'); return ['dashboard']; }
        setActiveTab(next[Math.max(0, prev.indexOf(cur) - 1)]);
        return next;
      });
      return;
    }
    if (c.action) handleToolbarAction(c.action);
  };

  const cmdFiltered = ALL_CMDS.filter(c => c.label.toLowerCase().includes(cmdQuery.toLowerCase()));

  const renderActive = () => {
    if (activeTab === 'agents' && shellAgent)
      return <AgentShell agent={shellAgent} onClose={() => setShellAgent(null)} />;

    if (activeTab === 'dashboard')
      return (
        <Suspense fallback={<div style={{ padding:20, color:'var(--tx3)' }}>[*] loading…</div>}>
          <DashboardView onNav={openTab} />
        </Suspense>
      );

    return (
      <>
        {activeTab === 'agents'     && <AgentsView onOpenShell={a => setShellAgent(a)} />}
        {activeTab === 'shell'      && <ShellModule />}
        {activeTab === 'payloads'   && <PayloadGenerator />}
        {activeTab === 'listeners'  && <ListenersView />}
        {activeTab === 'network'    && <NetworkView />}
        {activeTab === 'settings'   && <SettingsView />}
        {activeTab === 'credentials'&& <CredentialsView />}
        {activeTab === 'loot'       && <LootView />}
        {activeTab === 'reports'    && <ReportsView />}
        {activeTab === 'users'      && <UsersView />}
        {activeTab === 'sweep'      && <SweepView />}
        {activeTab === 'operations' && <OperationsView />}
        {activeTab === 'mitre'      && <MitreView />}
        {activeTab === 'playbooks'  && <PlaybooksView />}
        {activeTab === 'files'      && <FileManagerView />}
        {activeTab === 'processes'  && <ProcessesView />}
        {activeTab === 'tunnels'    && <TunnelsView />}
        {activeTab === 'implants'   && <ImplantsView />}
        {activeTab === 'exploits'   && <ExploitsView />}
        {activeTab === 'arsenal'    && <ArsenalView />}
        {activeTab === 'opsec'      && <OpsecView />}
        {activeTab === 'timeline'   && <TimelineView events={feed} />}
        {activeTab === 'clipboard'  && <ClipboardView />}
        {activeTab === 'logs' && (
          <div style={{ height:'100%', overflowY:'auto', padding:'6px 0' }}>
            {!feed.length && (
              <div style={{ padding:'10px 12px', fontSize:11, color:'var(--tx3)' }}>[*] No events — no agents connected</div>
            )}
            {feed.map((ev, i) => (
              <div key={i} className="feed-item" style={{ display:'flex', alignItems:'baseline' }}>
                <span style={{ fontSize:10, color:'var(--tx3)', minWidth:60, fontFamily:'Courier New', flexShrink:0 }}>{ev.time}</span>
                <span className={FEED_CLS[ev.type]} style={{ minWidth:28, flexShrink:0 }}>{FEED_ICO[ev.type]}</span>
                <span style={{ color:'var(--tx1)', marginLeft:8 }}>{ev.msg}</span>
              </div>
            ))}
          </div>
        )}
      </>
    );
  };

  return (
    <div style={{ display:'flex', flexDirection:'column', height:'100vh', overflow:'hidden', background:'var(--bg)', fontFamily:'var(--ui)' }}>

      <Menubar
        onNav={openTab}
        onToggleBottom={() => setShowBottom(s => !s)}
        onRefresh={() => loadRef.current()}
        onToolbarAction={handleToolbarAction}
        agentStats={agentStats}
      />

      {/* ── Workspace ── */}
      <div style={{ flex:1, display:'flex', overflow:'hidden', minHeight:0 }}>

        <Sidebar active={activeTab} onNav={openTab} width={sidebarW} />
        <div className="resize-handle" onMouseDown={onResizeStart} />

        <div style={{ flex:1, display:'flex', flexDirection:'column', overflow:'hidden', minWidth:0 }}>

          {/* Document tab bar */}
          <div className="ide-tab-bar">
            {openTabs.map(tab => (
              <div
                key={tab}
                className={`ide-tab${activeTab === tab ? ' active' : ''}`}
                onClick={() => { setActiveTab(tab); if (tab !== 'agents') setShellAgent(null); }}
              >
                <span className="ide-tab-icon">{VIEW_ICONS[tab]}</span>
                <span>{VIEW_LABELS[tab]}</span>
                {shellAgent && activeTab === tab && tab === 'agents' && (
                  <span style={{ fontSize:9, color:'var(--red)', marginLeft:3 }}>:{shellAgent.id.slice(0, 8)}</span>
                )}
                <span className="ide-tab-close" onClick={e => closeTab(tab, e)}>×</span>
              </div>
            ))}
            <div style={{ flex:1 }} />
          </div>

          {/* Content */}
          <div style={{ flex:1, overflow:'hidden', minHeight:0, background:'var(--bg)' }}>
            {renderActive()}
          </div>

          {/* Bottom panel */}
          {showBottom && (
            <div className="bottom-panel" style={{ height:188 }}>
              <div className="bottom-panel-hdr">
                <span className={`bottom-tab${bottomTab==='events'?' active':''}`} onClick={()=>setBottomTab('events')}>Event Log</span>
                <span className={`bottom-tab${bottomTab==='output'?' active':''}`} onClick={()=>setBottomTab('output')}>Output</span>
                <div style={{ marginLeft:'auto', display:'flex', alignItems:'center', gap:1, paddingRight:4 }}>
                  <button
                    style={{ width:18, height:18, background:'transparent', border:'none', color:'var(--tx3)', cursor:'pointer', fontSize:11, display:'flex', alignItems:'center', justifyContent:'center' }}
                    title="Clear log"
                    onClick={() => setFeed([])}
                  >⊟</button>
                  <button className="bottom-panel-close" onClick={() => setShowBottom(false)} title="Hide panel">×</button>
                </div>
              </div>
              <div style={{ flex:1, overflowY:'auto', minHeight:0 }}>
                {bottomTab === 'events' && (
                  !feed.length
                    ? <div style={{ padding:'8px 10px', fontSize:11, color:'var(--tx3)' }}>[*] Waiting for agent events…</div>
                    : feed.map((ev, i) => (
                        <div key={i} className="feed-item" style={{ display:'flex', gap:0, alignItems:'baseline' }}>
                          <span style={{ fontSize:10, color:'var(--tx3)', minWidth:58, fontFamily:'Courier New', flexShrink:0 }}>{ev.time}</span>
                          <span className={FEED_CLS[ev.type]} style={{ minWidth:30, fontSize:11, flexShrink:0 }}>{FEED_ICO[ev.type]}</span>
                          <span style={{ color:'var(--tx1)', fontSize:11 }}>{ev.msg}</span>
                        </div>
                      ))
                )}
                {bottomTab === 'output' && (
                  <div style={{ padding:'8px 10px', fontSize:11, color:'var(--tx3)', fontFamily:'Courier New' }}>
                    [*] No output — run a command or script to see output here.
                  </div>
                )}
              </div>
              <div style={{ height:24, borderTop:'1px solid var(--b1)', display:'flex', alignItems:'center', gap:6, padding:'0 10px', flexShrink:0, background:'var(--inset2)' }}>
                <span style={{ fontSize:12, color:'var(--red-hi)', fontFamily:'Courier New', flexShrink:0 }}>$&gt;</span>
                <input
                  value={cmd}
                  onChange={e => setCmd(e.target.value)}
                  style={{ flex:1, background:'transparent', border:'none', color:'var(--tx1)', fontFamily:'var(--ui)', fontSize:11, outline:'none' }}
                  placeholder="c2 command..."
                />
              </div>
            </div>
          )}
        </div>
      </div>

      {/* ── Status bar ── */}
      <div className="ide-status">
        <span className="status-seg on">● C2 ONLINE</span>
        <span className="status-seg">0.0.0.0:4444</span>
        <span className="status-seg">DB: CONNECTED</span>
        <span className="status-seg">
          Agents:&nbsp;<span style={{ color: agentStats.online > 0 ? 'var(--green)' : 'var(--tx2)' }}>{agentStats.online}</span>
          <span style={{ color:'var(--tx3)' }}>&nbsp;/&nbsp;{agentStats.total}</span>
        </span>
        {!showBottom && (
          <span
            className="status-seg"
            style={{ cursor:'pointer', color:'var(--tx3)' }}
            onClick={() => setShowBottom(true)}
            title="Show Bottom Panel"
          >⊟ Panel</span>
        )}
        <span style={{ marginLeft:'auto', padding:'0 8px', color:'var(--tx3)', fontSize:10 }}>
          ⌘K — Command Palette · Ctrl+W — Close Tab
        </span>
        <span className="status-seg" style={{ borderRight:'none', color:'var(--tx3)' }}>ZK v3.0.1</span>
      </div>

      {/* ── Command Palette ── */}
      {showCmdPalette && (
        <div
          onClick={() => setShowCmdPalette(false)}
          style={{ position:'fixed', inset:0, zIndex:9000, background:'rgba(0,0,0,0.62)', display:'flex', alignItems:'flex-start', justifyContent:'center', paddingTop:72 }}
        >
          <div
            onClick={e => e.stopPropagation()}
            style={{ width:520, background:'var(--panel)', border:'1px solid var(--b3)', boxShadow:'0 20px 60px rgba(0,0,0,0.85)', maxHeight:440, display:'flex', flexDirection:'column' }}
          >
            <div style={{ display:'flex', alignItems:'center', gap:8, padding:'8px 12px', borderBottom:'1px solid var(--b2)' }}>
              <span style={{ color:'var(--tx3)', fontSize:12 }}>⌨</span>
              <input
                autoFocus
                value={cmdQuery}
                onChange={e => setCmdQuery(e.target.value)}
                placeholder="Search views, run commands…"
                style={{ flex:1, background:'transparent', border:'none', color:'var(--tx0)', fontFamily:'var(--ui)', fontSize:13, outline:'none' }}
                onKeyDown={e => {
                  if (e.key === 'Escape') setShowCmdPalette(false);
                  if (e.key === 'Enter' && cmdFiltered.length > 0) execCmd(cmdFiltered[0]);
                }}
              />
              <span style={{ fontSize:10, color:'var(--tx3)', border:'1px solid var(--b2)', padding:'1px 5px' }}>ESC</span>
            </div>
            <div style={{ overflowY:'auto' }}>
              {!cmdFiltered.length && (
                <div style={{ padding:'12px 14px', color:'var(--tx3)', fontSize:11 }}>No results for "{cmdQuery}"</div>
              )}
              {cmdFiltered.map((c, i) => (
                <div
                  key={i}
                  onClick={() => execCmd(c)}
                  style={{ display:'flex', alignItems:'center', gap:10, padding:'7px 14px', cursor:'pointer', fontSize:12, color:'var(--tx1)' }}
                  onMouseEnter={e => (e.currentTarget.style.background = 'var(--red2)')}
                  onMouseLeave={e => (e.currentTarget.style.background = 'transparent')}
                >
                  <span style={{ color:'var(--tx3)', width:16, textAlign:'center', fontSize:11 }}>{c.icon}</span>
                  <span style={{ flex:1 }}>{c.label}</span>
                  <span style={{ fontSize:10, color:'var(--tx3)', border:'1px solid var(--b1)', padding:'1px 5px' }}>{c.cat}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* ── Kill All Modal ── */}
      {showKillModal && (
        <div
          onClick={() => setShowKillModal(false)}
          style={{ position:'fixed', inset:0, zIndex:9000, background:'rgba(0,0,0,0.7)', display:'flex', alignItems:'center', justifyContent:'center' }}
        >
          <div
            onClick={e => e.stopPropagation()}
            style={{ width:380, background:'var(--panel)', border:'1px solid var(--red)', boxShadow:'0 0 40px rgba(204,68,68,0.25)' }}
          >
            <div style={{ padding:'10px 14px', borderBottom:'1px solid var(--red3)', display:'flex', alignItems:'center', gap:8 }}>
              <span style={{ color:'var(--red-hi)', fontSize:12, fontWeight:700 }}>⊘ Kill All Agents</span>
            </div>
            <div style={{ padding:'16px 16px' }}>
              <div style={{ fontSize:11, color:'var(--tx1)', marginBottom:12, lineHeight:1.7 }}>
                Send KILL command to all&nbsp;
                <span style={{ color:'var(--red-hi)', fontWeight:700 }}>{agentStats.total}</span>
                &nbsp;agents. All sessions will be terminated immediately.
              </div>
              <div style={{ background:'var(--red3)', border:'1px solid var(--red)', padding:'6px 10px', fontSize:10, color:'var(--red-hi)' }}>
                [!] This action cannot be undone.
              </div>
            </div>
            <div style={{ padding:'10px 16px', borderTop:'1px solid var(--b1)', display:'flex', gap:8, justifyContent:'flex-end' }}>
              <button className="zk-btn" onClick={() => setShowKillModal(false)}>Cancel</button>
              <button className="zk-btn danger" onClick={() => setShowKillModal(false)}>Kill All ({agentStats.total})</button>
            </div>
          </div>
        </div>
      )}

      {showNewList && <NewListenerModal onClose={() => setShowNewList(false)} />}
      {showNewPay  && <NewPayloadModal  onClose={() => setShowNewPay(false)}  />}
    </div>
  );
}
