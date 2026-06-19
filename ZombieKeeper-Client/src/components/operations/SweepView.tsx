import { useState } from 'react';

const MOCK_AGENTS = [
  { id:'ZK-001', host:'WIN-DC01',    os:'Windows', priv:'SYSTEM', status:'ONLINE'  },
  { id:'ZK-002', host:'UBUNTU-WEB',  os:'Linux',   priv:'root',   status:'ONLINE'  },
  { id:'ZK-003', host:'WIN-WS03',    os:'Windows', priv:'User',   status:'ONLINE'  },
  { id:'ZK-004', host:'CENTOS-DB',   os:'Linux',   priv:'root',   status:'OFFLINE' },
  { id:'ZK-005', host:'WIN-EXCH01',  os:'Windows', priv:'SYSTEM', status:'ONLINE'  },
  { id:'ZK-006', host:'DEBIAN-PROXY',os:'Linux',   priv:'www-data',status:'ONLINE' },
];

const PRESETS = [
  { label:'whoami',          cmd:'whoami /all' },
  { label:'net users',       cmd:'net user' },
  { label:'ps list',         cmd:'Get-Process | Select-Object Name,Id,CPU | ft' },
  { label:'netstat',         cmd:'netstat -ano' },
  { label:'env dump',        cmd:'Get-ChildItem Env: | ft' },
  { label:'arp table',       cmd:'arp -a' },
  { label:'ifconfig',        cmd:'ip addr show' },
  { label:'cron jobs',       cmd:'crontab -l 2>/dev/null; ls /etc/cron*' },
  { label:'sudo check',      cmd:'sudo -l 2>/dev/null' },
  { label:'suid bins',       cmd:'find / -perm -4000 2>/dev/null | head -20' },
];

type ResultStatus = 'pending'|'running'|'done'|'error'|'offline';

interface AgentResult {
  id: string; host: string; os: string; priv: string;
  status: ResultStatus; output: string; exitCode: number|null; ms: number|null;
}

const S_COL: Record<ResultStatus,string> = {
  pending:'#333', running:'#d48b55', done:'#33a84a', error:'#e05c6e', offline:'#2a2a2a',
};

export default function SweepView() {
  const [cmd,      setCmd]      = useState('');
  const [mode,     setMode]     = useState<'all'|'online'|'windows'|'linux'|'root'>('online');
  const [results,  setResults]  = useState<AgentResult[]>([]);
  const [sweeping, setSweeping] = useState(false);
  const [selected, setSelected] = useState<Set<string>>(new Set(MOCK_AGENTS.map(a=>a.id)));

  const targets = MOCK_AGENTS.filter(a => {
    if (mode === 'all')     return true;
    if (mode === 'online')   return a.status === 'ONLINE';
    if (mode === 'windows')  return a.os === 'Windows' && a.status === 'ONLINE';
    if (mode === 'linux')    return a.os === 'Linux'   && a.status === 'ONLINE';
    if (mode === 'root')     return (a.priv === 'root' || a.priv === 'SYSTEM') && a.status === 'ONLINE';
    return false;
  }).filter(a => selected.has(a.id));

  const sweep = () => {
    if (!cmd.trim() || sweeping) return;
    setSweeping(true);
    const init: AgentResult[] = targets.map(a => ({
      id:a.id, host:a.host, os:a.os, priv:a.priv,
      status: a.status === 'OFFLINE' ? 'offline' : 'running',
      output:'', exitCode:null, ms:null,
    }));
    setResults(init);
    // TODO: replace with real WebSocket sweep — ws.send({ type:'sweep', cmd, agentIds:[...] })
    targets.forEach((a, i) => {
      if (a.status === 'OFFLINE') return;
      setTimeout(() => {
        const ok = Math.random() > 0.15;
        setResults(prev => prev.map(r => r.id !== a.id ? r : {
          ...r,
          status:    ok ? 'done' : 'error',
          exitCode:  ok ? 0 : 1,
          ms:        Math.floor(80 + Math.random() * 600),
          output:    ok
            ? `${a.host}\\${a.priv}\n> ${cmd}\n${a.os === 'Windows' ? 'NT AUTHORITY\\SYSTEM' : 'root'}`
            : `error: permission denied`,
        }));
        if (i === targets.length - 1) setSweeping(false);
      }, 300 + i * 250 + Math.random() * 400);
    });
  };

  const toggle = (id: string) =>
    setSelected(p => { const s = new Set(p); s.has(id) ? s.delete(id) : s.add(id); return s; });

  return (
    <div style={{ display:'flex', height:'100%', overflow:'hidden', fontFamily:'Courier New' }}>

      {/* LEFT — agent selector */}
      <div style={{ width:220, background:'#0d0d0d', borderRight:'1px solid #1a1a1a', display:'flex', flexDirection:'column', flexShrink:0 }}>
        <div style={{ padding:'8px 10px', borderBottom:'1px solid #1a1a1a', fontSize:9, color:'#444', textTransform:'uppercase', letterSpacing:1 }}>
          Target Filter
        </div>
        <div style={{ padding:'8px 10px', borderBottom:'1px solid #1a1a1a' }}>
          {(['all','online','windows','linux','root'] as const).map(m => (
            <div key={m} onClick={()=>setMode(m)} style={{
              padding:'3px 8px', fontSize:11, cursor:'pointer', marginBottom:2,
              color: mode===m ? '#e05c6e' : '#444',
              background: mode===m ? '#1a0000' : 'transparent',
              border: mode===m ? '1px solid #3d1520' : '1px solid transparent',
            }}>{m.toUpperCase()}</div>
          ))}
        </div>
        <div style={{ fontSize:9, color:'#2a2a2a', padding:'6px 10px', textTransform:'uppercase', letterSpacing:1 }}>Agents</div>
        <div style={{ flex:1, overflowY:'auto' }}>
          {MOCK_AGENTS.map(a => (
            <div key={a.id} onClick={()=>toggle(a.id)} style={{
              padding:'5px 10px', borderBottom:'1px solid #111', cursor:'pointer',
              opacity: a.status === 'OFFLINE' ? 0.3 : 1,
              background: selected.has(a.id) ? '#0a0a12' : 'transparent',
            }}>
              <div style={{ display:'flex', gap:6, alignItems:'center' }}>
                <div style={{ width:5, height:5, borderRadius:'50%', flexShrink:0,
                  background: a.status==='ONLINE' ? '#33a84a' : '#2a2a2a' }}/>
                <span style={{ fontSize:10, color: selected.has(a.id) ? '#cccccc' : '#444' }}>{a.id}</span>
              </div>
              <div style={{ fontSize:9, color:'#2a2a2a', paddingLeft:11 }}>{a.host}</div>
            </div>
          ))}
        </div>
        <div style={{ padding:'8px 10px', borderTop:'1px solid #1a1a1a', fontSize:10, color:'#333' }}>
          {targets.length} targets selected
        </div>
      </div>

      {/* RIGHT — command + results */}
      <div style={{ flex:1, display:'flex', flexDirection:'column', overflow:'hidden' }}>

        {/* Command bar */}
        <div style={{ padding:'10px 14px', background:'#0d0d0d', borderBottom:'1px solid #1a1a1a', flexShrink:0 }}>
          <div style={{ fontSize:9, color:'#333', textTransform:'uppercase', letterSpacing:1, marginBottom:6 }}>Sweep Command</div>
          <div style={{ display:'flex', gap:8, marginBottom:8 }}>
            <input value={cmd} onChange={e=>setCmd(e.target.value)}
              onKeyDown={e=>e.key==='Enter'&&sweep()}
              placeholder="command to execute on all targets..."
              style={{ flex:1, background:'#040404', border:'1px solid #1e1e1e', color:'#cccccc', fontFamily:'Courier New', fontSize:12, padding:'6px 10px', outline:'none' }}/>
            <button onClick={sweep} disabled={sweeping||!cmd.trim()||targets.length===0} style={{
              background: sweeping?'#0d0d0d':'#1a0000',
              border:`1px solid ${sweeping?'#222':'#e05c6e'}`,
              color: sweeping?'#333':'#e05c6e',
              fontFamily:'Courier New', fontSize:11, fontWeight:700,
              padding:'6px 18px', cursor: sweeping?'default':'pointer', letterSpacing:1,
            }}>
              {sweeping ? '[ SWEEPING... ]' : '[ EXECUTE SWEEP ]'}
            </button>
          </div>
          {/* Presets */}
          <div style={{ display:'flex', gap:6, flexWrap:'wrap' }}>
            {PRESETS.map(p => (
              <button key={p.label} onClick={()=>setCmd(p.cmd)} style={{
                background:'#080808', border:'1px solid #1a1a1a', color:'#444',
                fontFamily:'Courier New', fontSize:9, padding:'2px 8px', cursor:'pointer',
              }}>{p.label}</button>
            ))}
          </div>
        </div>

        {/* Results grid */}
        <div style={{ flex:1, overflowY:'auto', padding:'10px 14px', display:'grid', gridTemplateColumns:'repeat(auto-fill,minmax(280px,1fr))', gap:8, alignContent:'start' }}>
          {results.length === 0 && (
            <div style={{ gridColumn:'1/-1', color:'#1a1a1a', fontSize:12, paddingTop:20 }}>
              [*] Select targets, enter a command and execute the sweep.
            </div>
          )}
          {results.map(r => (
            <div key={r.id} style={{ background:'#0d0d0d', border:`1px solid ${S_COL[r.status]}22`, padding:'10px' }}>
              <div style={{ display:'flex', justifyContent:'space-between', marginBottom:6 }}>
                <div>
                  <span style={{ fontSize:11, color:'#cccccc', fontWeight:700 }}>{r.id}</span>
                  <span style={{ fontSize:10, color:'#333', marginLeft:8 }}>{r.host}</span>
                </div>
                <div style={{ display:'flex', gap:6, alignItems:'center' }}>
                  {r.ms !== null && <span style={{ fontSize:9, color:'#2a2a2a' }}>{r.ms}ms</span>}
                  <span style={{ fontSize:9, color:S_COL[r.status], fontWeight:700, textTransform:'uppercase' }}>{r.status}</span>
                </div>
              </div>
              <div style={{ background:'#040404', border:'1px solid #111', padding:'6px 8px', minHeight:40, fontFamily:'Courier New', fontSize:10, color: r.status==='error'?'#e05c6e':'#555', whiteSpace:'pre-wrap', wordBreak:'break-all' }}>
                {r.status==='running' ? '...' : r.status==='pending' ? '' : r.output || '(no output)'}
              </div>
              {r.exitCode !== null && (
                <div style={{ fontSize:9, color: r.exitCode===0?'#33a84a':'#e05c6e', marginTop:4 }}>
                  exit: {r.exitCode} · {r.os} · {r.priv}
                </div>
              )}
            </div>
          ))}
        </div>

        {/* Summary bar */}
        {results.length > 0 && (
          <div style={{ padding:'5px 14px', background:'#0d0d0d', borderTop:'1px solid #1a1a1a', display:'flex', gap:16, fontSize:10, flexShrink:0 }}>
            {(['done','running','error','offline'] as ResultStatus[]).map(s => {
              const count = results.filter(r=>r.status===s).length;
              return count > 0 ? <span key={s} style={{ color:S_COL[s] }}>{s}: {count}</span> : null;
            })}
          </div>
        )}
      </div>
    </div>
  );
}
