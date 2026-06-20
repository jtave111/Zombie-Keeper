import { useState, useEffect, useRef } from 'react';
import { Agent } from '@/lib/models/agents/agentModel';
import { shellWsUrl } from '@/lib/client/api';

interface ShellLine {
  type: 'cmd' | 'ok' | 'err' | 'warn' | 'sys' | 'info';
  text: string;
  time: string;
}

type WsStatus = 'connecting' | 'connected' | 'disconnected' | 'error';

const TABS = ['Shell', 'Process List', 'File Manager', 'Port Forward', 'Sysinfo'];

const now = () => {
  const d = new Date();
  return `${d.getHours().toString().padStart(2,'0')}:${d.getMinutes().toString().padStart(2,'0')}:${d.getSeconds().toString().padStart(2,'0')}`;
};

const stripAnsi = (s: string) =>
  s.replace(/\x1B\[[0-9;]*[A-Za-z]/g, '').replace(/\r\n/g, '\n').replace(/\r/g, '\n');

export default function AgentShell({ agent, onClose }: { agent: Agent; onClose: () => void }) {
  const [tab, setTab]           = useState('Shell');
  const [lines, setLines]       = useState<ShellLine[]>([
    { type:'sys',  text:`[*] Session opened: ${agent.id} — ${agent.ip} (${agent.hostname})`, time:now() },
    { type:'sys',  text:`[*] User: ${agent.user} | Priv: ${agent.priv} | OS: ${agent.os}`, time:now() },
    { type:'info', text:'[*] Connecting to shell...', time:now() },
  ]);
  const [input, setInput]       = useState('');
  const [history, setHistory]   = useState<string[]>([]);
  const [histIdx, setHistIdx]   = useState(-1);
  const [wsStatus, setWsStatus] = useState<WsStatus>('connecting');
  const bottomRef               = useRef<HTMLDivElement>(null);
  const inputRef                = useRef<HTMLInputElement>(null);
  const wsRef                   = useRef<WebSocket | null>(null);

  useEffect(() => {
    const ws = new WebSocket(shellWsUrl(agent._uuid ?? undefined));
    wsRef.current = ws;

    ws.onopen = () => {
      setWsStatus('connected');
      setLines(prev => [...prev, { type:'ok', text:'[+] Shell connected', time:now() }]);
    };

    ws.onmessage = (e) => {
      const raw = stripAnsi(e.data as string);
      const parts = raw.split('\n').filter(s => s.length > 0);
      if (!parts.length) return;
      const t = now();
      setLines(prev => [...prev, ...parts.map(text => ({ type: 'ok' as const, text, time: t }))]);
    };

    ws.onerror = () => {
      setWsStatus('error');
      setLines(prev => [...prev, { type:'err', text:'[-] WebSocket error — check API connection', time:now() }]);
    };

    ws.onclose = () => {
      setWsStatus('disconnected');
      setLines(prev => [...prev, { type:'sys', text:'[*] Shell disconnected', time:now() }]);
    };

    return () => { ws.close(); };
  }, []);

  useEffect(() => { bottomRef.current?.scrollIntoView({ behavior:'smooth' }); }, [lines]);
  useEffect(() => { inputRef.current?.focus(); }, [tab]);

  const execCmd = (cmd: string) => {
    const trimmed = cmd.trim();
    if (!trimmed) return;
    const t = now();

    setLines(prev => [...prev, { type:'cmd', text:`${agent.user}@${agent.hostname} $ ${trimmed}`, time:t }]);

    if (trimmed === 'clear') { setLines([]); return; }
    if (trimmed === 'exit')  { onClose(); return; }

    if (wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send(trimmed + '\n');
    } else {
      setLines(prev => [...prev, { type:'err', text:'[-] Shell not connected', time:t }]);
    }

    setHistory(p => [trimmed, ...p.slice(0, 49)]);
    setHistIdx(-1);
  };

  const handleKey = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter') { execCmd(input); setInput(''); }
    else if (e.key === 'ArrowUp') {
      e.preventDefault();
      const idx = Math.min(histIdx + 1, history.length - 1);
      setHistIdx(idx);
      setInput(history[idx] ?? '');
    }
    else if (e.key === 'ArrowDown') {
      e.preventDefault();
      const idx = Math.max(histIdx - 1, -1);
      setHistIdx(idx);
      setInput(idx === -1 ? '' : history[idx] ?? '');
    }
  };

  const LINE_COLOR: Record<string, string> = {
    cmd:  '#cccccc', ok: '#33a84a', err: '#e05c6e',
    warn: '#d48b55', sys: '#555555', info: '#5bb8d4',
  };

  const WS_INDICATOR: Record<WsStatus, { color: string; label: string }> = {
    connecting:   { color: '#d48b55', label: 'CONNECTING' },
    connected:    { color: '#33a84a', label: 'CONNECTED'  },
    disconnected: { color: '#444444', label: 'DISCONNECTED' },
    error:        { color: '#e05c6e', label: 'ERROR'      },
  };

  const privColor = agent.priv === 'ROOT' ? '#e05c6e' : '#888888';

  return (
    <div style={{ display:'flex', flexDirection:'column', height:'100%', overflow:'hidden', background:'var(--inset2)' }}>

      {/* ── HEADER ── */}
      <div style={{ background:'var(--inset)', borderBottom:'1px solid #2a2a2a', padding:'8px 16px', flexShrink:0, display:'flex', alignItems:'center', gap:16 }}>
        <div style={{ display:'flex', alignItems:'center', gap:10 }}>
          <div style={{ width:7, height:7, borderRadius:'50%', background:'#33a84a' }}/>
          <span style={{ fontSize:13, fontWeight:700, color:'#cccccc', fontFamily:'Courier New' }}>{agent.id}</span>
          <span style={{ fontSize:11, color:'var(--tx1)' }}>—</span>
          <span style={{ fontSize:12, color:'#5bb8d4', fontFamily:'Courier New' }}>{agent.ip}</span>
          <span style={{ fontSize:11, color:'var(--tx1)' }}>({agent.hostname})</span>
        </div>
        <div style={{ display:'flex', gap:12, fontSize:11, fontFamily:'Courier New' }}>
          <span><span style={{ color:'var(--tx1)' }}>user: </span><span style={{ color:privColor }}>{agent.user}</span></span>
          <span><span style={{ color:'var(--tx1)' }}>priv: </span><span style={{ color:privColor, fontWeight:700 }}>{agent.priv}</span></span>
          <span><span style={{ color:'var(--tx1)' }}>os: </span><span style={{ color:'#888' }}>{agent.os}</span></span>
          <span><span style={{ color:'var(--tx1)' }}>arch: </span><span style={{ color:'#888' }}>{agent.arch}</span></span>
        </div>
        <button onClick={onClose} style={{ marginLeft:'auto', background:'transparent', border:'1px solid #2a2a2a', color:'var(--tx1)', fontFamily:'Courier New', fontSize:11, padding:'3px 12px', cursor:'pointer' }}>
          [X] CLOSE SESSION
        </button>
      </div>

      {/* ── TABS ── */}
      <div style={{ display:'flex', background:'var(--inset2)', borderBottom:'1px solid #222', flexShrink:0 }}>
        {TABS.map(t => (
          <div key={t} onClick={() => setTab(t)} style={{
            padding:'5px 16px', fontSize:12, fontFamily:'Courier New',
            color: tab === t ? 'var(--tx0)' : 'var(--tx2)',
            borderRight:'1px solid #1a1a1a',
            borderTop: tab === t ? '2px solid #e05c6e' : '2px solid transparent',
            background: tab === t ? '#080808' : 'transparent',
            cursor:'pointer',
          }}>
            {t}
          </div>
        ))}
      </div>

      {/* ── CONTENT ── */}
      {tab === 'Shell' && (
        <div style={{ flex:1, display:'flex', flexDirection:'column', overflow:'hidden' }} onClick={() => inputRef.current?.focus()}>
          <div style={{ flex:1, overflowY:'auto', padding:'10px 14px', fontFamily:'Courier New', fontSize:12, background:'var(--inset2)' }}>
            {lines.map((l, i) => (
              <div key={i} style={{ display:'flex', gap:10, lineHeight:'1.6', alignItems:'baseline' }}>
                {l.time && <span style={{ color:'var(--tx2)', fontSize:10, minWidth:60, flexShrink:0 }}>{l.time}</span>}
                <span style={{ color: LINE_COLOR[l.type], whiteSpace:'pre-wrap', wordBreak:'break-all' }}>{l.text}</span>
              </div>
            ))}
            <div ref={bottomRef}/>
          </div>

          <div style={{ display:'flex', alignItems:'center', gap:8, padding:'8px 14px', borderTop:'1px solid #1a1a1a', background:'var(--inset2)', flexShrink:0 }}>
            <span style={{ color:'#e05c6e', fontFamily:'Courier New', fontSize:12, whiteSpace:'nowrap', fontWeight:700 }}>
              {agent.user}@{agent.hostname} $&gt;
            </span>
            <input ref={inputRef} value={input} onChange={e => setInput(e.target.value)} onKeyDown={handleKey}
              disabled={wsStatus !== 'connected'}
              style={{ flex:1, background:'transparent', border:'none', color: wsStatus === 'connected' ? '#cccccc' : '#444', fontFamily:'Courier New', fontSize:12, outline:'none', cursor: wsStatus === 'connected' ? 'text' : 'not-allowed' }}
              autoFocus />
          </div>
        </div>
      )}

      {tab === 'Process List' && (
        <div style={{ flex:1, overflow:'auto', background:'var(--inset2)' }}>
          <table style={{ width:'100%', borderCollapse:'collapse', fontFamily:'Courier New', fontSize:12 }}>
            <thead>
              <tr style={{ background:'var(--inset)', borderBottom:'1px solid #222', position:'sticky', top:0 }}>
                {['PID','PPID','NAME','USER','CPU','MEM','STATUS'].map(h => (
                  <th key={h} style={{ padding:'5px 12px', color:'var(--tx2)', fontWeight:400, textAlign:'left', borderRight:'1px solid #1a1a1a', fontSize:11, textTransform:'uppercase' }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {[
                ['1','0','/sbin/init','root','0.0','0.1','S'],
                ['512','1','sshd','root','0.0','0.2','S'],
                ['1024','512','bash','root','0.0','0.1','S'],
                ['2248','1','nginx','www-data','0.1','1.2','S'],
                ['3310','1','cron','root','0.0','0.1','S'],
                ['4421','1','bash','root','0.0','0.1','S <-- ZK'],
                ['7810','4421','python3','root','2.1','8.4','R'],
              ].map(row => (
                <tr key={row[0]} style={{ borderBottom:'1px solid #111', cursor:'pointer' }}
                  onMouseEnter={e => (e.currentTarget.style.background='#111')}
                  onMouseLeave={e => (e.currentTarget.style.background='transparent')}>
                  {row.map((cell, ci) => (
                    <td key={ci} style={{ padding:'5px 12px', color: row[5]==='S <-- ZK' ? '#e05c6e' : ci===2?'#d48b55':ci===3?'#888':'#888', borderRight:'1px solid #111' }}>
                      {cell}
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {tab === 'File Manager' && (
        <div style={{ flex:1, display:'flex', overflow:'hidden', background:'var(--inset2)' }}>
          <div style={{ flex:1, display:'flex', flexDirection:'column' }}>
            <div style={{ padding:'6px 12px', background:'var(--inset2)', borderBottom:'1px solid #222', display:'flex', gap:8, alignItems:'center' }}>
              <span style={{ color:'var(--tx1)', fontSize:11, fontFamily:'Courier New' }}>Path:</span>
              <span style={{ color:'#5bb8d4', fontSize:12, fontFamily:'Courier New' }}>/root</span>
              <button style={{ marginLeft:'auto', background:'transparent', border:'1px solid #2a2a2a', color:'#888', fontFamily:'Courier New', fontSize:10, padding:'2px 8px', cursor:'pointer' }}>Upload</button>
              <button style={{ background:'transparent', border:'1px solid #2a2a2a', color:'#888', fontFamily:'Courier New', fontSize:10, padding:'2px 8px', cursor:'pointer' }}>Refresh</button>
            </div>
            <div style={{ flex:1, overflowY:'auto' }}>
              <table style={{ width:'100%', borderCollapse:'collapse', fontFamily:'Courier New', fontSize:12 }}>
                <thead>
                  <tr style={{ background:'var(--inset)', borderBottom:'1px solid #222' }}>
                    {['Name','Size','Type','Modified','Perms'].map(h => (
                      <th key={h} style={{ padding:'5px 12px', color:'var(--tx2)', fontWeight:400, textAlign:'left', fontSize:11, textTransform:'uppercase', borderRight:'1px solid #1a1a1a' }}>{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {[
                    ['../','—','dir','—','drwxr-xr-x'],
                    ['.ssh/','—','dir','2024-01-10','drwx------'],
                    ['.bash_history','4.2 KB','file','2024-01-15','rw-------'],
                    ['.bashrc','3.1 KB','file','2023-12-01','rw-r--r--'],
                    ['passwords.txt','512 B','file','2024-01-12','rw-------'],
                    ['id_rsa','1.7 KB','file','2023-11-20','rw-------'],
                  ].map(row => (
                    <tr key={row[0]} style={{ borderBottom:'1px solid #111', cursor:'pointer' }}
                      onMouseEnter={e=>(e.currentTarget.style.background='#111')}
                      onMouseLeave={e=>(e.currentTarget.style.background='transparent')}>
                      <td style={{ padding:'5px 12px', color: row[2]==='dir'?'#5bb8d4':row[0].includes('password')||row[0].includes('id_rsa')?'#e05c6e':'#888', borderRight:'1px solid #111' }}>{row[0]}</td>
                      <td style={{ padding:'5px 12px', color:'var(--tx1)', borderRight:'1px solid #111' }}>{row[1]}</td>
                      <td style={{ padding:'5px 12px', color:'var(--tx1)', borderRight:'1px solid #111' }}>{row[2]}</td>
                      <td style={{ padding:'5px 12px', color:'var(--tx1)', borderRight:'1px solid #111' }}>{row[3]}</td>
                      <td style={{ padding:'5px 12px', color:'var(--tx2)' }}>{row[4]}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {tab === 'Port Forward' && (
        <div style={{ flex:1, padding:'16px', overflow:'auto', background:'var(--inset2)', fontFamily:'Courier New' }}>
          <div style={{ marginBottom:16, fontSize:10, color:'var(--tx2)', textTransform:'uppercase', letterSpacing:1 }}>Port Forwarding Rules</div>
          <div style={{ display:'flex', gap:8, marginBottom:16 }}>
            <input style={{ background:'var(--inset2)', border:'1px solid #2a2a2a', color:'#cccccc', fontFamily:'Courier New', fontSize:12, padding:'5px 8px', width:120 }} placeholder="Local port" />
            <input style={{ background:'var(--inset2)', border:'1px solid #2a2a2a', color:'#cccccc', fontFamily:'Courier New', fontSize:12, padding:'5px 8px', flex:1 }} placeholder="Remote host:port" />
            <button style={{ background:'#1a0000', border:'1px solid #e05c6e', color:'#e05c6e', fontFamily:'Courier New', fontSize:11, padding:'5px 14px', cursor:'pointer' }}>Add Rule</button>
          </div>
          <table style={{ width:'100%', borderCollapse:'collapse', fontSize:12 }}>
            <thead>
              <tr style={{ background:'var(--inset)', borderBottom:'1px solid #222' }}>
                {['Local','Remote','Status','Action'].map(h=>(
                  <th key={h} style={{ padding:'5px 12px', color:'var(--tx2)', fontWeight:400, textAlign:'left', fontSize:11, textTransform:'uppercase' }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              <tr style={{ borderBottom:'1px solid #111' }}>
                <td style={{ padding:'5px 12px', color:'#5bb8d4' }}>:8080</td>
                <td style={{ padding:'5px 12px', color:'#888' }}>10.0.0.1:80</td>
                <td style={{ padding:'5px 12px', color:'#33a84a' }}>[*] ACTIVE</td>
                <td style={{ padding:'5px 12px' }}><button style={{ background:'transparent', border:'1px solid #e05c6e', color:'#e05c6e', fontFamily:'Courier New', fontSize:10, padding:'1px 8px', cursor:'pointer' }}>Stop</button></td>
              </tr>
            </tbody>
          </table>
        </div>
      )}

      {tab === 'Sysinfo' && (
        <div style={{ flex:1, overflow:'auto', padding:'16px', background:'var(--inset2)', fontFamily:'Courier New', fontSize:12 }}>
          <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr', gap:12 }}>
            {[
              { title:'SYSTEM', rows:[['Hostname',agent.hostname],['OS',agent.os],['Arch',agent.arch],['Kernel','—']] },
              { title:'AGENT', rows:[['ID',agent.id],['User',agent.user],['Privilege',agent.priv],['Last Seen',agent.lastSeen]] },
              { title:'NETWORK', rows:[['IP',agent.ip],['MAC',agent.mac],['IPv6','—'],['Status',agent.status]] },
              { title:'SESSION', rows:[['Shell',WS_INDICATOR[wsStatus].label],['Beacon','—'],['Jitter','—'],['Priv',agent.priv]] },
            ].map(card => (
              <div key={card.title} style={{ background:'var(--inset2)', border:'1px solid #222' }}>
                <div style={{ padding:'5px 12px', background:'var(--inset)', borderBottom:'1px solid #222', fontSize:9, color:'var(--tx2)', textTransform:'uppercase', letterSpacing:1 }}>{card.title}</div>
                {card.rows.map(([k,v]) => (
                  <div key={k} style={{ display:'flex', padding:'6px 12px', borderBottom:'1px solid #111' }}>
                    <span style={{ color:'var(--tx1)', minWidth:90 }}>{k}:</span>
                    <span style={{ color: k==='Privilege'&&v==='ROOT'?'#e05c6e':k==='IP'?'#5bb8d4':k==='Shell'?WS_INDICATOR[wsStatus].color:'#888' }}>{v}</span>
                  </div>
                ))}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* ── STATUS BAR ── */}
      <div style={{ height:20, background:'var(--inset2)', borderTop:'1px solid #1a1a1a', display:'flex', alignItems:'center', padding:'0 14px', gap:20, fontSize:10, fontFamily:'Courier New', flexShrink:0 }}>
        <span style={{ color: WS_INDICATOR[wsStatus].color }}>[*] {WS_INDICATOR[wsStatus].label}</span>
        <span style={{ color:'var(--tx2)' }}>agent: {agent.id}</span>
        <span style={{ marginLeft:'auto', color:'var(--tx2)' }}>Press [X] to close</span>
      </div>
    </div>
  );
}
