'use client';
import { useState, useEffect } from 'react';
import { Agent, AgentGeo } from '@/lib/data';
import { agentsApi, c2Api, toAgent, toAgentGeo, BackendAgent, C2Info } from '@/lib/api';
import dynamic from 'next/dynamic';

const WorldMap = dynamic<{ geoAgents: AgentGeo[]; c2: C2Info | null }>(() => import('./WorldMap'), {
  ssr: false,
  loading: () => <div style={{flex:1,background:'#050a0e',display:'flex',alignItems:'center',justifyContent:'center',color:'#1a1a1a',fontFamily:'Courier New',fontSize:11}}>LOADING MAP...</div>,
});

interface Props { onNav?: (v:string) => void; }

export default function DashboardView({ onNav }: Props) {
  const [rawAgents, setRawAgents] = useState<BackendAgent[]>([]);
  const [c2,        setC2]        = useState<C2Info | null>(null);

  useEffect(() => {
    agentsApi.list().then(setRawAgents).catch(console.error);
    c2Api.info().then(setC2).catch(console.error);
  }, []);

  const agents: Agent[]   = rawAgents.map(toAgent);
  const geoAgents: AgentGeo[] = rawAgents.map(toAgentGeo).filter((g): g is AgentGeo => g !== null);

  const online = agents.filter(a=>a.status==='ONLINE').length;
  const idle   = agents.filter(a=>a.status==='IDLE').length;
  const lost   = agents.filter(a=>a.status==='LOST').length;
  const roots  = agents.filter(a=>a.priv==='ROOT').length;

  return (
    <div style={{ display:'flex', flexDirection:'column', height:'100%', overflow:'hidden', background:'#080808', fontFamily:'Courier New' }}>

      {/* ── STAT CARDS ── */}
      <div style={{ display:'flex', gap:0, flexShrink:0, borderBottom:'1px solid #1a1a1a' }}>
        {[
          { label:'ACTIVE AGENTS', value:online,        sub:`${idle} idle · ${lost} lost`,  accent:'#33a84a', subCls:'' },
          { label:'C2 SERVERS',    value:'1 / 1',        sub:'all operational',              accent:'#d48b55', subCls:'t-ok' },
          { label:'TOTAL AGENTS',  value:agents.length,  sub:'registered',                  accent:'#5bb8d4', subCls:'t-ok' },
          { label:'LOST AGENTS',   value:lost,           sub:'timeout / no response',       accent:'#e05c6e', subCls:'t-err' },
          { label:'ROOT SESSIONS', value:roots,          sub:`of ${agents.length} agents`,  accent:'#e05c6e', subCls:'t-err' },
          { label:'SYSTEM LOAD',   value:'—',            sub:'monitor',                     accent:'#d48b55', subCls:'t-warn' },
        ].map((s,i) => (
          <div key={i} style={{
            flex:1, padding:'12px 14px', borderRight:'1px solid #1a1a1a',
            borderTop:`2px solid ${s.accent}`, background:'#0d0d0d',
          }}>
            <div style={{ fontSize:9, color:'#444', textTransform:'uppercase', letterSpacing:'1px', marginBottom:6 }}>{s.label}</div>
            <div style={{ fontSize:24, fontWeight:700, color:'#cccccc', lineHeight:1, marginBottom:4 }}>{s.value}</div>
            <div className={s.subCls} style={{ fontSize:11, color:s.subCls?undefined:'#444' }}>{s.sub}</div>
          </div>
        ))}
      </div>

      {/* ── MAIN: World Map (left) + System Health (right) ── */}
      <div style={{ flex:1, display:'flex', overflow:'hidden', minHeight:0 }}>

        {/* WORLD MAP */}
        <div style={{ flex:1, display:'flex', flexDirection:'column', overflow:'hidden' }}>
          <WorldMap geoAgents={geoAgents} c2={c2} />
        </div>

        {/* SYSTEM HEALTH */}
        <div style={{ width:280, display:'flex', flexDirection:'column', overflow:'hidden', borderLeft:'1px solid #1a1a1a', flexShrink:0 }}>
          <div style={{ flex:1, display:'flex', flexDirection:'column', overflow:'hidden' }}>
            <div style={{ padding:'5px 12px', background:'#111', borderBottom:'1px solid #1a1a1a', fontSize:10, color:'#444', textTransform:'uppercase', letterSpacing:1, flexShrink:0 }}>
              System Health
            </div>
            <div style={{ flex:1, overflowY:'auto' }}>
              {[
                { label:'C2 Listener',   value:'0.0.0.0:4444', status:'ONLINE',    ok:true },
                { label:'HTTP Listener', value:'0.0.0.0:8443', status:'ONLINE',    ok:true },
                { label:'Database',      value:'localhost:3306',status:'CONNECTED', ok:true },
                { label:'Spring Boot',   value:'port 8080',    status:'RUNNING',   ok:true },
                { label:'Beacon',        value:'10s',          status:'',          ok:true },
                { label:'Jitter',        value:'23%',          status:'',          ok:true },
                { label:'Threads',       value:'14',           status:'',          ok:true },
                { label:'Uptime',        value:'—',            status:'',          ok:true },
                { label:'Memory',        value:'—',            status:'',          ok:true },
                { label:'CPU Load',      value:'—',            status:'',          ok:true },
                { label:'Disk Free',     value:'—',            status:'',          ok:true },
                { label:'Last Backup',   value:'—',            status:'',          ok:true },
              ].map(item => (
                <div key={item.label} style={{ display:'flex', justifyContent:'space-between', alignItems:'center', padding:'6px 12px', borderBottom:'1px solid #0d0d0d' }}
                  onMouseEnter={e=>(e.currentTarget.style.background='#111')}
                  onMouseLeave={e=>(e.currentTarget.style.background='transparent')}>
                  <span style={{ fontSize:11, color:'#555' }}>{item.label}</span>
                  <div style={{ display:'flex', alignItems:'center', gap:8 }}>
                    <span style={{ fontSize:11, color:'#777', fontFamily:'Courier New' }}>{item.value}</span>
                    {item.status && (
                      <span style={{
                        fontSize:9, padding:'1px 5px', border:'1px solid',
                        borderColor: item.ok?'#1e4028':'#3d1520',
                        color: item.ok?'#33a84a':'#e05c6e',
                        background: item.ok?'#0a1a0e':'#1a0808',
                      }}>{item.status}</span>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* AGENT STATUS */}
          <div style={{ flexShrink:0, borderTop:'1px solid #1a1a1a' }}>
            <div style={{ padding:'5px 12px', background:'#111', borderBottom:'1px solid #1a1a1a', fontSize:10, color:'#444', textTransform:'uppercase', letterSpacing:1 }}>Agent Status</div>
            <div style={{ padding:'8px 12px', display:'flex', gap:14, fontSize:12 }}>
              <span className="status-on">[*] {online} online</span>
              <span className="status-idle">[~] {idle} idle</span>
              <span className="status-lost">[!] {lost} lost</span>
            </div>
            <div style={{ padding:'0 12px 10px', display:'flex', gap:14, fontSize:11 }}>
              <span style={{ color:'#555' }}>ROOT: <span style={{ color:'#e05c6e', fontWeight:700 }}>{roots}</span></span>
              <span style={{ color:'#555' }}>USER: <span style={{ color:'#666' }}>{agents.length-roots}</span></span>
            </div>
          </div>

          {/* QUICK NAV */}
          <div style={{ flexShrink:0, borderTop:'1px solid #1a1a1a' }}>
            <div style={{ padding:'5px 12px', background:'#111', borderBottom:'1px solid #1a1a1a', fontSize:10, color:'#444', textTransform:'uppercase', letterSpacing:1 }}>Quick Nav</div>
            <div style={{ padding:'6px 8px', display:'flex', flexWrap:'wrap', gap:5 }}>
              {[['Agents','agents'],['Network','network'],['Logs','logs'],['Settings','settings']].map(([label,key])=>(
                <button key={key} onClick={()=>onNav?.(key)} style={{
                  background:'#0d0d0d', border:'1px solid #1a1a1a', color:'#555',
                  fontFamily:'Courier New', fontSize:11, padding:'4px 10px', cursor:'pointer',
                }}
                  onMouseEnter={e=>{e.currentTarget.style.borderColor='#e05c6e';e.currentTarget.style.color='#e05c6e';}}
                  onMouseLeave={e=>{e.currentTarget.style.borderColor='#1a1a1a';e.currentTarget.style.color='#555';}}>
                  {label}
                </button>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
