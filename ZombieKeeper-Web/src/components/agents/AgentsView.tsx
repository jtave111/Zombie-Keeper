'use client';
import { useState, useEffect, useCallback } from 'react';
import { Agent, AgentStatus } from '@/lib/models/agents/agentModel';
import { agentsApi, toAgent, BackendAgentDto } from '@/lib/api';

const SYM: Record<AgentStatus,string> = { ONLINE:'[*]', IDLE:'[~]', LOST:'[!]' };
const CLS: Record<AgentStatus,string> = { ONLINE:'status-on', IDLE:'status-idle', LOST:'status-lost' };
const FILTERS: { key:AgentStatus|'ALL'; label:string }[] = [
  { key:'ALL', label:'ALL' }, { key:'ONLINE', label:'ONLINE' },
  { key:'IDLE', label:'IDLE' }, { key:'LOST', label:'LOST' },
];

interface Props { onOpenShell?: (a:Agent) => void; }

export default function AgentsView({ onOpenShell }: Props) {
  const [rawAgents, setRawAgents] = useState<BackendAgentDto[]>([]);
  const [loading,   setLoading]   = useState(true);
  const [error,     setError]     = useState('');
  const [filter,    setFilter]    = useState<AgentStatus|'ALL'>('ALL');
  const [search,    setSearch]    = useState('');
  const [selected,  setSelected]  = useState<string|null>(null);
  const [clickTimer, setClickTimer] = useState<ReturnType<typeof setTimeout>|null>(null);

  const load = useCallback(() => {
    setLoading(true);
    setError('');
    agentsApi.list()
      .then(list => { setRawAgents(list); setLoading(false); })
      .catch(e  => { setError(e.message ?? 'fetch error'); setLoading(false); });
  }, []);

  useEffect(() => { load(); }, [load]);

  type AgentWithUUID = Agent & { _uuid: string };
  const allAgents: AgentWithUUID[] = rawAgents.map(b => ({ ...toAgent(b), _uuid: b.id }));

  const agents = allAgents.filter(a => {
    const mf = filter==='ALL' || a.status===filter;
    const ms = !search || Object.values(a).some(v => String(v).toLowerCase().includes(search.toLowerCase()));
    return mf && ms;
  });

  const handleRowClick = (agent: AgentWithUUID) => {
    if (clickTimer) {
      clearTimeout(clickTimer); setClickTimer(null);
      onOpenShell?.(agent);
    } else {
      const t = setTimeout(() => {
        setSelected(agent.id===selected ? null : agent.id);
        setClickTimer(null);
      }, 240);
      setClickTimer(t);
    }
  };

  const handleKill = async (e: React.MouseEvent, uuid: string) => {
    e.stopPropagation();
    if (!confirm('Kill this agent?')) return;
    await agentsApi.remove(uuid).catch(console.error);
    setRawAgents(prev => prev.filter(a => a.id !== uuid));
    if (selected) setSelected(null);
  };

  const online = allAgents.filter(a=>a.status==='ONLINE').length;
  const idle   = allAgents.filter(a=>a.status==='IDLE').length;
  const lost   = allAgents.filter(a=>a.status==='LOST').length;

  return (
    <div style={{ display:'flex', flexDirection:'column', height:'100%', overflow:'hidden' }}>

      {/* TOOLBAR */}
      <div style={{ display:'flex', alignItems:'center', gap:6, padding:'6px 10px', background:'#111', borderBottom:'1px solid #222', flexShrink:0 }}>
        <input className="zk-input" style={{ width:220 }} placeholder="search agents..."
          value={search} onChange={e=>setSearch(e.target.value)} />
        <span style={{ fontSize:11, color:'#2a2a2a' }}>|</span>
        {FILTERS.map(f => (
          <button key={f.key} className={`zk-btn${filter===f.key?' active':''}`} onClick={()=>setFilter(f.key)}>{f.label}</button>
        ))}
        <div style={{ marginLeft:'auto', fontSize:11, color:'#444' }}>{agents.length} session{agents.length!==1?'s':''}</div>
        <button className="zk-btn" style={{ marginLeft:6 }} onClick={load}>Refresh</button>
        <button className="zk-btn danger">Kill All</button>
      </div>

      <div style={{ padding:'3px 10px', background:'#0d0d0d', borderBottom:'1px solid #111', flexShrink:0, fontSize:10, color:'#2a2a2a', fontFamily:'Courier New' }}>
        Double-click row to open agent shell · Single-click to inspect
      </div>

      {/* TABLE */}
      <div style={{ flex:1, overflow:'auto' }}>
        {loading && (
          <div style={{ padding:'20px', color:'#2a2a2a', fontFamily:'Courier New', fontSize:11 }}>[*] Loading agents...</div>
        )}
        {error && (
          <div style={{ padding:'20px', color:'#e05c6e', fontFamily:'Courier New', fontSize:11 }}>[-] {error}</div>
        )}
        {!loading && !error && agents.length === 0 && (
          <div style={{ padding:'20px', color:'#2a2a2a', fontFamily:'Courier New', fontSize:11 }}>[*] No agents connected</div>
        )}
        {!loading && !error && agents.length > 0 && (
          <table className="zk-table">
            <thead>
              <tr>
                <th>ID</th><th>Status</th><th>IP Address</th><th>MAC</th><th>Hostname</th>
                <th>User</th><th>Priv</th><th>OS</th><th>Process</th><th>PID</th>
                <th>Arch</th><th>Last Seen</th><th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {agents.map(agent => (
                <tr key={agent.id} className={selected===agent.id?'selected':''}
                  onClick={()=>handleRowClick(agent)} style={{ cursor:'pointer' }}>
                  <td className="cell-id">{agent.id}</td>
                  <td><span className={CLS[agent.status]}>{SYM[agent.status]}</span></td>
                  <td className="cell-ip">{agent.ip}</td>
                  <td className="cell-dim" style={{ fontSize:11 }}>{agent.mac}</td>
                  <td style={{ color:'#888' }}>{agent.hostname}</td>
                  <td style={{ color:'#666' }}>{agent.user}</td>
                  <td className={agent.priv==='ROOT'?'priv-root':'priv-user'}>{agent.priv}</td>
                  <td className="cell-dim">{agent.os}</td>
                  <td className="cell-proc">{agent.process}</td>
                  <td className="cell-dim">{agent.pid}</td>
                  <td className="cell-dim">{agent.arch}</td>
                  <td className="cell-dim">{agent.lastSeen}</td>
                  <td>
                    <div style={{ display:'flex', gap:4 }}>
                      <button className="zk-btn active" style={{ fontSize:10, padding:'2px 7px' }}
                        onClick={e=>{e.stopPropagation(); onOpenShell?.(agent);}}>Shell</button>
                      <button className="zk-btn" style={{ fontSize:10, padding:'2px 7px' }}>Info</button>
                      <button className="zk-btn danger" style={{ fontSize:10, padding:'2px 7px' }}
                        onClick={e=>handleKill(e, agent._uuid)}>Kill</button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {/* DETAIL PANEL */}
      {selected && (() => {
        const a = agents.find(x=>x.id===selected);
        if (!a) return null;
        return (
          <div style={{ borderTop:'1px solid #222', background:'#0d0d0d', padding:'8px 14px', flexShrink:0, fontFamily:'Courier New', fontSize:11 }}>
            <div style={{ color:'#333', marginBottom:6, fontSize:10, letterSpacing:1 }}>AGENT DETAIL — {a.id}</div>
            <div style={{ display:'grid', gridTemplateColumns:'repeat(4,1fr)', gap:'4px 20px', marginBottom:8 }}>
              {[['Hostname',a.hostname],['IP',a.ip],['MAC',a.mac],['OS',a.os],
                ['User',a.user],['Priv',a.priv],['Process',`${a.process} (${a.pid})`],['Arch',a.arch]].map(([k,v])=>(
                <div key={k} style={{ display:'flex', gap:8 }}>
                  <span style={{ color:'#333', minWidth:60 }}>{k}:</span>
                  <span style={{ color:'#5bb8d4' }}>{v}</span>
                </div>
              ))}
            </div>
            <button className="zk-btn active" style={{ marginRight:6 }} onClick={()=>onOpenShell?.(a)}>Open Shell</button>
            <button className="zk-btn" style={{ marginRight:6 }}>Sysinfo</button>
            <button className="zk-btn danger" onClick={e=>handleKill(e, a._uuid)}>Kill Agent</button>
          </div>
        );
      })()}

      {/* STATUS BAR */}
      <div style={{ padding:'3px 10px', background:'#111', borderTop:'1px solid #1a1a1a', flexShrink:0, display:'flex', gap:20, fontSize:11, fontFamily:'Courier New' }}>
        <span className="status-on">[*] {online} online</span>
        <span className="status-idle">[~] {idle} idle</span>
        <span className="status-lost">[!] {lost} lost</span>
      </div>
    </div>
  );
}
