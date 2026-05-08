'use client';
import { useState, useEffect } from 'react';
import { Agent, AgentStatus } from '@/lib/data';
import { agentsApi, toAgent } from '@/lib/api';

const SYM: Record<AgentStatus,string> = { ONLINE:'[*]', IDLE:'[~]', LOST:'[!]' };
const CLS: Record<AgentStatus,string> = { ONLINE:'status-on', IDLE:'status-idle', LOST:'status-lost' };
const TABS = ['Agents','Listeners','Credentials','Loot','Proxy Pivots'];

export default function AgentTableHeader({ onSelectAgent }: { onSelectAgent?:(id:string)=>void }) {
  const [sel,       setSel]       = useState<string|null>(null);
  const [activeTab, setActiveTab] = useState(0);
  const [agents,    setAgents]    = useState<Agent[]>([]);

  useEffect(() => {
    agentsApi.list()
      .then(list => setAgents(list.map(toAgent)))
      .catch(console.error);
  }, []);

  return (
    <div style={{ flexShrink:0, background:'var(--inset)', borderBottom:'1px solid var(--b2)' }}>
      <div style={{ display:'flex', background:'var(--inset)', borderBottom:'1px solid var(--b1)' }}>
        {TABS.map((tab, i) => (
          <div key={tab} onClick={() => setActiveTab(i)} style={{
            padding:'4px 14px', fontSize:11,
            color: activeTab===i ? 'var(--tx0)' : 'var(--tx2)',
            borderRight:'1px solid var(--b1)',
            borderTop: activeTab===i ? '2px solid var(--red)' : '2px solid transparent',
            background: activeTab===i ? 'var(--panel)' : 'transparent',
            cursor:'pointer',
          }}>{tab}{i === 0 ? ` [${agents.length}]` : ''}</div>
        ))}
      </div>
      <div style={{ maxHeight:130, overflow:'auto' }}>
        <table className="zk-table" style={{ fontSize:11 }}>
          <thead>
            <tr>
              <th>ID</th><th>Status</th><th>Internal IP</th><th>Hostname</th><th>User</th>
              <th>Priv</th><th>OS</th><th>Process</th><th>PID</th><th>Arch</th><th>Last Seen</th>
            </tr>
          </thead>
          <tbody>
            {agents.map(a => (
              <tr key={a.id} className={sel===a.id ? 'selected' : ''} style={{ cursor:'pointer' }}
                onClick={() => { setSel(a.id); onSelectAgent?.(a.id); }}
                onDoubleClick={() => onSelectAgent?.('shell:' + a.id)}>
                <td className="cell-id">{a.id}</td>
                <td><span className={CLS[a.status]}>{SYM[a.status]}</span></td>
                <td className="cell-ip">{a.ip}</td>
                <td style={{ color:'var(--tx0)' }}>{a.hostname}</td>
                <td style={{ color:'var(--tx1)' }}>{a.user}</td>
                <td className={a.priv==='ROOT'?'priv-root':'priv-user'}>{a.priv}</td>
                <td className="cell-dim">{a.os}</td>
                <td className="cell-proc">{a.process}</td>
                <td className="cell-dim">{a.pid}</td>
                <td className="cell-dim">{a.arch}</td>
                <td className="cell-dim">{a.lastSeen}</td>
              </tr>
            ))}
            {agents.length === 0 && (
              <tr><td colSpan={11} style={{ color:'#2a2a2a', padding:'8px 10px', fontFamily:'Courier New', fontSize:10 }}>[*] No agents</td></tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
