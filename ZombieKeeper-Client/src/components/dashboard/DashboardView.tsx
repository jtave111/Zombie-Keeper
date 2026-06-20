import { useState, useEffect } from 'react';
import { Agent, AgentGeo } from '@/lib/models/agents/agentModel';
import { agentsApi, c2Api, toAgent, toAgentGeo, BackendAgentDto, C2Info } from '@/lib/client/api';
import { lazy, Suspense } from 'react';

const WorldMap = lazy(() => import('./WorldMap'));

interface Props { onNav?: (v: string) => void; }

const STAT_CARDS = (online: number, total: number, lost: number, roots: number, idle: number) => [
  { label:'ACTIVE AGENTS',  value: online,        sub:`${idle} idle · ${lost} lost`,   accent:'var(--green)',  valCol:'var(--green)' },
  { label:'LOST AGENTS',    value: lost,           sub:'timeout / no response',         accent:'var(--red)',    valCol: lost > 0 ? 'var(--red-hi)' : 'var(--tx2)' },
  { label:'TOTAL AGENTS',   value: total,          sub:'registered',                   accent:'var(--cyan)',   valCol:'var(--tx0)' },
  { label:'ROOT SESSIONS',  value: roots,          sub:`of ${total} agents`,            accent:'var(--red)',    valCol: roots > 0 ? 'var(--red-hi)' : 'var(--tx2)' },
  { label:'C2 SERVERS',     value:'1 / 1',         sub:'all operational',              accent:'var(--orange)', valCol:'var(--tx0)' },
  { label:'SYSTEM LOAD',    value:'—',             sub:'monitoring',                   accent:'var(--tx3)',    valCol:'var(--tx2)' },
];

export default function DashboardView({ onNav }: Props) {
  const [rawAgents, setRawAgents] = useState<BackendAgentDto[]>([]);
  const [c2,        setC2]        = useState<C2Info | null>(null);

  useEffect(() => {
    agentsApi.list().then(setRawAgents).catch(console.error);
    c2Api.info().then(setC2).catch(console.error);
  }, []);

  const agents: Agent[]    = rawAgents.map(toAgent);
  const geoAgents: AgentGeo[] = rawAgents.map(toAgentGeo).filter((g): g is AgentGeo => g !== null);

  const online = agents.filter(a => a.status === 'ONLINE').length;
  const idle   = agents.filter(a => a.status === 'IDLE').length;
  const lost   = agents.filter(a => a.status === 'LOST').length;
  const roots  = agents.filter(a => a.priv  === 'ROOT').length;

  return (
    <div style={{ display:'flex', flexDirection:'column', height:'100%', overflow:'hidden', background:'var(--bg)', fontFamily:'var(--ui)' }}>

      {/* ── Stat cards ── */}
      <div style={{ display:'flex', gap:0, flexShrink:0, borderBottom:'1px solid var(--b1)' }}>
        {STAT_CARDS(online, agents.length, lost, roots, idle).map((s, i) => (
          <div key={i} style={{
            flex:1, padding:'10px 14px',
            borderRight:'1px solid var(--b1)',
            borderTop:`2px solid ${s.accent}`,
            background:'var(--panel)',
          }}>
            <div style={{ fontSize:9, color:'var(--tx3)', textTransform:'uppercase', letterSpacing:'1px', marginBottom:5 }}>{s.label}</div>
            <div style={{ fontSize:22, fontWeight:700, color:s.valCol, lineHeight:1, marginBottom:3 }}>{s.value}</div>
            <div style={{ fontSize:10, color:'var(--tx2)' }}>{s.sub}</div>
          </div>
        ))}
      </div>

      {/* ── World Map + System Health ── */}
      <div style={{ flex:1, display:'flex', overflow:'hidden', minHeight:0 }}>

        {/* World Map */}
        <div style={{ flex:1, display:'flex', flexDirection:'column', overflow:'hidden' }}>
          <Suspense fallback={
            <div style={{ flex:1, background:'var(--inset)', display:'flex', alignItems:'center', justifyContent:'center', color:'var(--tx3)', fontSize:11 }}>
              LOADING MAP...
            </div>
          }>
            <WorldMap geoAgents={geoAgents} c2={c2} />
          </Suspense>
        </div>

        {/* System Health */}
        <div style={{ width:272, display:'flex', flexDirection:'column', overflow:'hidden', borderLeft:'1px solid var(--b1)', flexShrink:0, background:'var(--inset2)' }}>

          {/* Health table */}
          <div className="sec-hdr">System Health</div>
          <div style={{ flex:1, overflowY:'auto' }}>
            {[
              { label:'C2 Listener',   value:'0.0.0.0:4444', status:'ONLINE',    ok:true  },
              { label:'HTTP Listener', value:'0.0.0.0:8443', status:'ONLINE',    ok:true  },
              { label:'Database',      value:'localhost:3306',status:'CONNECTED', ok:true  },
              { label:'Spring Boot',   value:'port 8080',    status:'RUNNING',   ok:true  },
              { label:'Beacon',        value:'10s',          status:'',          ok:true  },
              { label:'Jitter',        value:'23%',          status:'',          ok:true  },
              { label:'Threads',       value:'14',           status:'',          ok:true  },
              { label:'Uptime',        value:'—',            status:'',          ok:true  },
              { label:'Memory',        value:'—',            status:'',          ok:true  },
              { label:'CPU Load',      value:'—',            status:'',          ok:true  },
              { label:'Disk Free',     value:'—',            status:'',          ok:true  },
            ].map(item => (
              <div
                key={item.label}
                style={{ display:'flex', justifyContent:'space-between', alignItems:'center', padding:'5px 10px', borderBottom:'1px solid var(--b1)' }}
                onMouseEnter={e => (e.currentTarget.style.background = 'var(--panel2)')}
                onMouseLeave={e => (e.currentTarget.style.background = 'transparent')}
              >
                <span style={{ fontSize:11, color:'var(--tx2)' }}>{item.label}</span>
                <div style={{ display:'flex', alignItems:'center', gap:8 }}>
                  <span style={{ fontSize:11, color:'var(--tx1)', fontFamily:'Courier New' }}>{item.value}</span>
                  {item.status && (
                    <span style={{ fontSize:9, padding:'1px 5px', border:'1px solid', borderColor: item.ok ? 'var(--green2)' : 'var(--red)', color: item.ok ? 'var(--green)' : 'var(--red-hi)', background: item.ok ? 'var(--green3)' : 'var(--red3)' }}>
                      {item.status}
                    </span>
                  )}
                </div>
              </div>
            ))}
          </div>

          {/* Agent summary */}
          <div style={{ flexShrink:0, borderTop:'1px solid var(--b1)' }}>
            <div className="sec-hdr">Agent Summary</div>
            <div style={{ padding:'8px 10px', display:'flex', gap:0, background:'var(--inset2)' }}>
              <div style={{ flex:1, textAlign:'center', borderRight:'1px solid var(--b1)' }}>
                <div style={{ fontSize:18, fontWeight:700, color:'var(--green)' }}>{online}</div>
                <div style={{ fontSize:9, color:'var(--tx3)', textTransform:'uppercase', letterSpacing:0.5 }}>Online</div>
              </div>
              <div style={{ flex:1, textAlign:'center', borderRight:'1px solid var(--b1)' }}>
                <div style={{ fontSize:18, fontWeight:700, color:'var(--orange)' }}>{idle}</div>
                <div style={{ fontSize:9, color:'var(--tx3)', textTransform:'uppercase', letterSpacing:0.5 }}>Idle</div>
              </div>
              <div style={{ flex:1, textAlign:'center', borderRight:'1px solid var(--b1)' }}>
                <div style={{ fontSize:18, fontWeight:700, color:'var(--red-hi)' }}>{lost}</div>
                <div style={{ fontSize:9, color:'var(--tx3)', textTransform:'uppercase', letterSpacing:0.5 }}>Lost</div>
              </div>
              <div style={{ flex:1, textAlign:'center' }}>
                <div style={{ fontSize:18, fontWeight:700, color: roots > 0 ? 'var(--red-hi)' : 'var(--tx2)' }}>{roots}</div>
                <div style={{ fontSize:9, color:'var(--tx3)', textTransform:'uppercase', letterSpacing:0.5 }}>Root</div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
