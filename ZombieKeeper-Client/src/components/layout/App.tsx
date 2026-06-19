import { useState, useEffect, lazy, Suspense } from 'react';
import Menubar from '@/components/layout/Menubar';
import Sidebar from '@/components/layout/Sidebar';
import AgentsView from '@/components/agents/AgentsView';
import AgentShell from '@/components/agents/AgentShell';
import ProcessesView from '@/components/agents/ProcessesView';
import NetworkView from '@/components/network/NetworkView';
import NetworkScannerView from '@/components/network/NetworkScannerView';
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
import { Agent, FeedEvent } from '@/lib/models/agents/agentModel';
import { agentsApi, toAgent, mapStatus } from '@/lib/client/api';

const DashboardView = lazy(() => import('@/components/dashboard/DashboardView'));

type View =
  'dashboard'|'agents'|'shell'|'payloads'|'network'|'scanner'|'logs'|'settings'|
  'listeners'|'credentials'|'loot'|'reports'|'users'|
  'sweep'|'operations'|'mitre'|'playbooks'|
  'files'|'processes'|'tunnels'|
  'implants'|'exploits'|'arsenal'|
  'opsec';

const VIEW_LABELS: Record<View,string> = {
  dashboard:'Dashboard', agents:'Agents', shell:'Shell', payloads:'Payload Generator',
  network:'Network Map', scanner:'Network Scanner',
  logs:'Logs', settings:'Settings', listeners:'Listeners',
  credentials:'Credentials', loot:'Loot', reports:'Reports', users:'Users',
  sweep:'Sweep', operations:'Op Planner', mitre:'MITRE ATT&CK', playbooks:'Playbooks',
  files:'File Manager', processes:'Processes', tunnels:'Tunnels',
  implants:'Implants', exploits:'Exploits', arsenal:'Arsenal Build',
  opsec:'IOC Tracker',
};

const FEED_CLS: Record<string,string> = { ok:'t-ok', err:'t-err', warn:'t-warn', sys:'t-sys' };
const FEED_ICO: Record<string,string> = { ok:'[+]', err:'[-]', warn:'[!]', sys:'[*]' };

function buildFeed(agents: Agent[]): FeedEvent[] {
  return agents.map(a => {
    const now  = new Date();
    const time = [now.getUTCHours(), now.getUTCMinutes(), now.getUTCSeconds()]
      .map(n=>String(n).padStart(2,'0')).join(':');
    if (a.status === 'ONLINE')
      return { type:'ok'   as const, msg:`${a.id} connected — ${a.hostname} (${a.priv})`, time };
    if (a.status === 'LOST')
      return { type:'err'  as const, msg:`${a.id} LOST — ${a.hostname} timeout`,           time };
    return   { type:'warn' as const, msg:`${a.id} idle — ${a.hostname}`,                  time };
  });
}

export default function App() {
  const [view,       setView]       = useState<View>('dashboard');
  const [cmd,        setCmd]        = useState('');
  const [shellAgent, setShellAgent] = useState<Agent|null>(null);
  const [agentStats, setAgentStats] = useState({ online:0, total:0 });
  const [feed,       setFeed]       = useState<FeedEvent[]>([]);

  useEffect(() => {
    const load = () =>
      agentsApi.list()
        .then(list => {
          const mapped = list.map(toAgent);
          setAgentStats({ online: list.filter(a=>mapStatus(a.status)==='ONLINE').length, total: list.length });
          setFeed(buildFeed(mapped));
        })
        .catch(console.error);
    load();
    const id = setInterval(load, 30_000);
    return () => clearInterval(id);
  }, []);

  const navigate = (k: string) => { setView(k as View); setShellAgent(null); };

  return (
    <div style={{ display:'flex', flexDirection:'column', height:'100vh', overflow:'hidden', background:'#080808', fontFamily:'Courier New' }}>
      <Menubar />

      <div style={{ flex:1, display:'flex', overflow:'hidden', minHeight:0 }}>
        <Sidebar active={view} onNav={navigate} />

        {/* CENTER CONTENT */}
        <div style={{ flex:1, display:'flex', flexDirection:'column', overflow:'hidden' }}>
          <div style={{ display:'flex', alignItems:'center', padding:'0 12px', height:22, background:'#0d0d0d', borderBottom:'1px solid #111', flexShrink:0, fontSize:11, gap:6, fontFamily:'Courier New' }}>
            <span style={{ color:'#2a2a2a' }}>ZK</span>
            <span style={{ color:'#2a2a2a' }}>/</span>
            <span style={{ color:'#444' }}>{VIEW_LABELS[view]}</span>
            {shellAgent && <>
              <span style={{ color:'#2a2a2a' }}>/</span>
              <span style={{ color:'#e05c6e' }}>Shell:{shellAgent.id}</span>
            </>}
          </div>
          <div style={{ flex:1, overflow:'hidden', minHeight:0 }}>
            <Suspense fallback={<div style={{ padding:20, color:'#333', fontFamily:'Courier New' }}>[*] loading…</div>}>
              {view==='dashboard'  && <DashboardView onNav={(v:string)=>setView(v as View)} />}
            </Suspense>
            {view==='agents' && (shellAgent
              ? <AgentShell agent={shellAgent} onClose={()=>setShellAgent(null)} />
              : <AgentsView onOpenShell={a=>setShellAgent(a)} />)}
            {view==='shell'       && <ShellModule />}
            {view==='payloads'    && <PayloadGenerator />}
            {view==='listeners'   && <ListenersView />}
            {view==='network'     && <NetworkView />}
            {view==='scanner'     && <NetworkScannerView />}
            {view==='settings'    && <SettingsView />}
            {view==='credentials' && <CredentialsView />}
            {view==='loot'        && <LootView />}
            {view==='reports'     && <ReportsView />}
            {view==='users'       && <UsersView />}
            {view==='sweep'       && <SweepView />}
            {view==='operations'  && <OperationsView />}
            {view==='mitre'       && <MitreView />}
            {view==='playbooks'   && <PlaybooksView />}
            {view==='files'       && <FileManagerView />}
            {view==='processes'   && <ProcessesView />}
            {view==='tunnels'     && <TunnelsView />}
            {view==='implants'    && <ImplantsView />}
            {view==='exploits'    && <ExploitsView />}
            {view==='arsenal'     && <ArsenalView />}
            {view==='opsec'       && <OpsecView />}
            {view==='logs'        && (
              <div style={{ padding:'10px 14px', height:'100%', overflowY:'auto', fontFamily:'Courier New' }}>
                <div style={{ marginBottom:10, fontSize:10, color:'#333', textTransform:'uppercase', letterSpacing:1 }}>System Event Log</div>
                {feed.length === 0 && <div style={{ color:'#2a2a2a', fontSize:11 }}>[*] No events — no agents connected</div>}
                {feed.map((ev,i)=>(
                  <div key={i} style={{ display:'flex', gap:10, padding:'4px 0', borderBottom:'1px solid #0d0d0d', fontSize:11 }}>
                    <span style={{ color:'#2a2a2a', minWidth:60 }}>{ev.time}</span>
                    <span className={FEED_CLS[ev.type]} style={{ minWidth:28 }}>{FEED_ICO[ev.type]}</span>
                    <span style={{ color:'#666' }}>{ev.msg}</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>

        {/* EVENT VIEWER */}
        <div style={{ width:252, background:'#0d0d0d', borderLeft:'1px solid #1a1a1a', display:'flex', flexDirection:'column', overflow:'hidden', flexShrink:0 }}>
          <div style={{ padding:'4px 10px', background:'#111', borderBottom:'1px solid #1a1a1a', fontSize:10, color:'#444', textTransform:'uppercase', letterSpacing:1, flexShrink:0, minHeight:24, display:'flex', alignItems:'center' }}>Event Viewer</div>
          <div style={{ flex:1, overflowY:'auto' }}>
            {feed.length === 0 && <div style={{ padding:'10px', fontSize:10, color:'#2a2a2a' }}>[*] No events</div>}
            {feed.map((ev,i)=>(
              <div key={i} style={{ padding:'6px 10px', borderBottom:'1px solid #111', fontSize:11 }}>
                <div style={{ display:'flex', gap:6 }}>
                  <span className={FEED_CLS[ev.type]} style={{ flexShrink:0 }}>{FEED_ICO[ev.type]}</span>
                  <span style={{ color:'#777', flex:1, lineHeight:1.4 }}>{ev.msg}</span>
                </div>
                <div style={{ fontSize:10, color:'#2a2a2a', marginTop:1, paddingLeft:18 }}>{ev.time}</div>
              </div>
            ))}
          </div>
          <div style={{ borderTop:'1px solid #1a1a1a', padding:'6px 10px', background:'#080808', flexShrink:0 }}>
            <div style={{ fontSize:9, color:'#2a2a2a', marginBottom:4, textTransform:'uppercase', letterSpacing:1 }}>Command</div>
            <div style={{ display:'flex', gap:6, alignItems:'center' }}>
              <span style={{ fontSize:12, color:'#e05c6e', whiteSpace:'nowrap' }}>$&gt;</span>
              <input value={cmd} onChange={e=>setCmd(e.target.value)}
                style={{ flex:1, background:'transparent', border:'none', color:'#777', fontFamily:'Courier New', fontSize:12, outline:'none' }}
                placeholder="command..." />
            </div>
          </div>
        </div>
      </div>

      {/* STATUS BAR */}
      <div style={{ height:18, background:'#080808', borderTop:'1px solid #0d0d0d', display:'flex', alignItems:'center', padding:'0 12px', gap:20, fontSize:10, fontFamily:'Courier New', flexShrink:0 }}>
        <span style={{ color:'#33a84a' }}>[*] C2 ONLINE</span>
        <span style={{ color:'#2a2a2a' }}>Listener: 0.0.0.0:4444</span>
        <span style={{ color:'#2a2a2a' }}>DB: CONNECTED</span>
        <span style={{ color:'#2a2a2a' }}>Agents: {agentStats.online} online / {agentStats.total} total</span>
        <span style={{ marginLeft:'auto', color:'#1a1a1a' }}>ZK v3.0.1 · Spring Boot · Java 21</span>
      </div>
    </div>
  );
}
