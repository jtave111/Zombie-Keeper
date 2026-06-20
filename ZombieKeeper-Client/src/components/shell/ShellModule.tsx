import { useState, useRef, useEffect, useCallback } from 'react';
import { Agent } from '@/lib/models/agents/agentModel';
import { agentsApi, toAgent, shellWsUrl } from '@/lib/client/api';

const stripAnsi = (s: string) =>
  s.replace(/\x1B\[[0-9;]*[A-Za-z]/g, '').replace(/\r\n/g, '\n').replace(/\r/g, '\n');

let _agents: Agent[] = [];

interface Line { type: string; text: string; time: string; }

const ts = () => {
  const d = new Date();
  return `${d.getHours().toString().padStart(2,'0')}:${d.getMinutes().toString().padStart(2,'0')}:${d.getSeconds().toString().padStart(2,'0')}`;
};

const C: Record<string, string> = {
  cmd:  '#cccccc',
  ok:   '#33a84a',
  err:  '#e05c6e',
  warn: '#d48b55',
  sys:  'var(--tx2)',
  info: '#5bb8d4',
  dim:  'var(--tx3)',
};

const HELP_TEXT = `
[*] ZOMBIE KEEPER C2 SHELL — Command Reference
───────────────────────────────────────────────
AGENT MANAGEMENT
  agents / sessions      List all active agent sessions
  info <id>              Show detailed info for agent
  interact <id>          Open interactive shell on agent
  kill <id>              Terminate agent session
  sleep <id> <s> [j%]   Set beacon interval + jitter
  rename <id> <name>     Rename agent alias

LISTENERS
  listeners              List all C2 listeners
  listener new           Create new listener (interactive)
  listener stop <id>     Stop a listener
  listener start <id>    Start a stopped listener

PAYLOADS
  payload list           List generated payloads
  payload gen            Generate new payload (interactive)
  payload stager <id>    Get one-liner stager for payload

CREDENTIALS & LOOT
  creds                  Dump collected credentials
  creds export           Export credentials to CSV
  loot                   List collected loot files
  loot get <id>          Download loot file

C2 SERVER
  status                 C2 server health and uptime
  config                 Show current C2 configuration
  reload                 Reload C2 configuration
  shutdown               Graceful C2 shutdown (confirm required)

OPERATORS
  operators              List connected operators
  kick <operator>        Disconnect an operator

DATABASE
  db status              Database connection status
  db backup              Trigger immediate DB backup
  db stats               Show database statistics

UTILITIES
  clear                  Clear terminal
  help                   Show this reference
  exit                   Close this shell
`.trim();

const COMMANDS: Record<string, (args: string[]) => Line[]> = {
  help: () => HELP_TEXT.split('\n').map(l => ({
    type: l.startsWith('[*]') ? 'ok' : l.startsWith('───') ? 'dim' : l.match(/^[A-Z]/) ? 'warn' : l.startsWith('  ') ? 'info' : 'sys',
    text: l, time: ts(),
  })),

  agents: () => [
    { type:'sys', text:'[*] Active sessions:', time:ts() },
    ..._agents.map(a => ({
      type: a.status === 'ONLINE' ? 'ok' : a.status === 'IDLE' ? 'warn' : 'err',
      text: `  ${a.id.padEnd(8)} ${a.ip.padEnd(16)} ${a.status.padEnd(8)} ${a.user.padEnd(12)} [${a.priv}]  ${a.os}  (${a.lastSeen})`,
      time: ts(),
    })),
    { type:'sys', text:`[*] Total: ${_agents.length} | Online: ${_agents.filter(a=>a.status==='ONLINE').length} | Idle: ${_agents.filter(a=>a.status==='IDLE').length} | Lost: ${_agents.filter(a=>a.status==='LOST').length}`, time:ts() },
  ],

  sessions: () => COMMANDS.agents([]),

  listeners: () => [
    { type:'sys', text:'[*] Active listeners:', time:ts() },
    { type:'ok',  text:'  [1]  HTTP   0.0.0.0:4444   ONLINE  agents:4', time:ts() },
    { type:'ok',  text:'  [2]  HTTPS  0.0.0.0:8443   ONLINE  agents:2', time:ts() },
    { type:'err', text:'  [3]  DNS    0.0.0.0:53     OFFLINE agents:0', time:ts() },
  ],

  status: () => [
    { type:'sys',  text:'[*] C2 Server Status', time:ts() },
    { type:'ok',   text:'  Framework   : ZOMBIE_KEEPER v3.0.1', time:ts() },
    { type:'ok',   text:'  Status      : ONLINE', time:ts() },
    { type:'ok',   text:'  Uptime      : 04:22:11', time:ts() },
    { type:'ok',   text:'  Database    : CONNECTED (mysql://localhost:3306)', time:ts() },
    { type:'ok',   text:'  Listeners   : 2 online / 3 total', time:ts() },
    { type:'ok',   text:'  Agents      : 4 online / 6 total', time:ts() },
    { type:'info', text:'  Threads     : 14 active', time:ts() },
    { type:'info', text:'  Memory      : 512 MB / 8192 MB', time:ts() },
    { type:'warn', text:'  CPU Load    : 87% [HIGH]', time:ts() },
    { type:'ok',   text:'  Disk Free   : 22 GB', time:ts() },
  ],

  config: () => [
    { type:'sys', text:'[*] Current C2 Configuration', time:ts() },
    { type:'info',text:'  listener.host    = 0.0.0.0', time:ts() },
    { type:'info',text:'  listener.port    = 4444', time:ts() },
    { type:'info',text:'  beacon.interval  = 10s', time:ts() },
    { type:'info',text:'  beacon.jitter    = 23%', time:ts() },
    { type:'info',text:'  auth.mode        = JWT + JSESSIONID', time:ts() },
    { type:'info',text:'  db.host          = localhost:3306', time:ts() },
    { type:'info',text:'  db.name          = zombie_keeper_db', time:ts() },
    { type:'info',text:'  log.level        = INFO', time:ts() },
    { type:'info',text:'  rbac.enabled     = true', time:ts() },
  ],

  creds: () => [
    { type:'sys',  text:'[*] Collected credentials:', time:ts() },
    { type:'ok',   text:'  [1] root:$6$hash... (linux/shadow) — ZK-001', time:ts() },
    { type:'ok',   text:'  [2] admin:Password1! (plaintext/env) — ZK-003', time:ts() },
    { type:'warn', text:'  [3] svc_acct:hash... (linux/shadow) — ZK-003', time:ts() },
    { type:'ok',   text:'  [4] AWS_ACCESS_KEY_ID=AKIA... — ZK-003', time:ts() },
    { type:'sys',  text:'[*] 4 credentials. Use "creds export" to dump CSV.', time:ts() },
  ],

  loot: () => [
    { type:'sys', text:'[*] Loot files:', time:ts() },
    { type:'ok',  text:'  [1] /etc/passwd     (ZK-001)  2.1 KB  2024-01-15', time:ts() },
    { type:'ok',  text:'  [2] /etc/shadow     (ZK-001)  1.8 KB  2024-01-15', time:ts() },
    { type:'ok',  text:'  [3] id_rsa          (ZK-001)  1.7 KB  2024-01-15', time:ts() },
    { type:'ok',  text:'  [4] passwords.txt   (ZK-001)  512 B   2024-01-15', time:ts() },
    { type:'warn',text:'  [5] screen_001.png  (ZK-002)  847 KB  2024-01-15', time:ts() },
  ],

  operators: () => [
    { type:'sys', text:'[*] Connected operators:', time:ts() },
    { type:'ok',  text:'  ROOT_ADMIN  [you]  ADMIN   connected 04:22:11', time:ts() },
    { type:'info',text:'  op_ghost           OPERATOR connected 00:14:33', time:ts() },
  ],

  'db': (args) => {
    if (args[0] === 'status') return [
      { type:'ok',  text:'[+] Database: CONNECTED', time:ts() },
      { type:'info',text:'  Host    : localhost:3306', time:ts() },
      { type:'info',text:'  Schema  : zombie_keeper_db', time:ts() },
      { type:'info',text:'  Pool    : 10/10 connections', time:ts() },
    ];
    if (args[0] === 'backup') return [
      { type:'sys', text:'[*] Triggering database backup...', time:ts() },
      { type:'ok',  text:'[+] Backup complete: /backups/zk_2024-01-15_042211.sql.gz', time:ts() },
    ];
    if (args[0] === 'stats') return [
      { type:'sys', text:'[*] Database statistics:', time:ts() },
      { type:'info',text:'  Agents      : 6 records', time:ts() },
      { type:'info',text:'  Sessions    : 142 total', time:ts() },
      { type:'info',text:'  Credentials : 4 collected', time:ts() },
      { type:'info',text:'  Loot files  : 5 items', time:ts() },
      { type:'info',text:'  Events      : 2,341 log entries', time:ts() },
    ];
    return [{ type:'err', text:'[-] Usage: db <status|backup|stats>', time:ts() }];
  },

  reload: () => [
    { type:'sys', text:'[*] Reloading C2 configuration...', time:ts() },
    { type:'ok',  text:'[+] Configuration reloaded. No restart required.', time:ts() },
  ],

  payload: (args) => {
    if (args[0] === 'list') return [
      { type:'sys',  text:'[*] Generated payloads:', time:ts() },
      { type:'ok',   text:'  [1] windows_x64.exe   HTTP/4444  2024-01-15  47.2 KB', time:ts() },
      { type:'info', text:'  [2] linux_x64.elf      HTTP/4444  2024-01-14  38.1 KB', time:ts() },
    ];
    if (args[0] === 'gen') return [{ type:'warn', text:'[!] Use the Payload Generator UI (Payloads tab)', time:ts() }];
    return [{ type:'err', text:'[-] Usage: payload <list|gen|stager <id>>', time:ts() }];
  },

  shutdown: () => [
    { type:'warn', text:'[!] WARNING: This will stop the C2 server.', time:ts() },
    { type:'warn', text:'[!] Type "shutdown confirm" to proceed.', time:ts() },
  ],

  'shutdown confirm': () => [
    { type:'err', text:'[-] Initiating graceful shutdown...', time:ts() },
    { type:'err', text:'[-] All agent sessions will be disconnected.', time:ts() },
    { type:'sys', text:'[*] (stub — wire to POST /api/c2/shutdown)', time:ts() },
  ],
};

const CMD_COMPLETIONS = [
  ...Object.keys(COMMANDS),
  'info','sleep','kill','interact','kick','rename',
];

const LOG_EVENTS = [
  { t:'02:08:22', c:'ok',  m:'Scan completed — 5 hosts, 14 ports discovered' },
  { t:'02:05:12', c:'err', m:'ZK-004 LOST — beacon timeout after 14m' },
  { t:'02:04:55', c:'ok',  m:'ZK-006 connected — CORP-DC-01 (ROOT)' },
  { t:'02:04:30', c:'warn',m:'Port 3389 detected on 192.168.1.200' },
  { t:'02:03:11', c:'ok',  m:'ZK-005 connected — WIN-SRV-03 (ROOT)' },
  { t:'02:01:09', c:'err', m:'Auth failure — bad credentials (x3) from 10.0.0.88' },
  { t:'01:58:33', c:'ok',  m:'ZK-001 privilege escalated to ROOT' },
  { t:'01:55:00', c:'sys', m:'Database backup completed — 12.4 MB' },
  { t:'01:44:11', c:'ok',  m:'ZK-002 connected — WIN-DEV-07 (USER)' },
  { t:'01:30:00', c:'sys', m:'C2 server started — ZK v3.0.1' },
];

type WsStatus = 'connecting'|'connected'|'error'|'closed';

export default function ShellModule() {
  const [lines,    setLines]  = useState<Line[]>([
    { type:'sys', text:'ZOMBIE KEEPER C2 — Interactive Operator Shell', time:ts() },
    { type:'sys', text:'─────────────────────────────────────────────', time:ts() },
    { type:'ok',  text:'[+] Authenticated as ROOT_ADMIN (ADMIN)', time:ts() },
    { type:'info',text:'[*] Type "help" for reference · Tab = autocomplete · ↑↓ = history', time:ts() },
  ]);
  const [input,    setInput]  = useState('');
  const [history,  setHist]   = useState<string[]>([]);
  const [histIdx,  setHIdx]   = useState(-1);
  const [tab,      setTab]    = useState<'shell'|'log'>('shell');
  const [agents,   setAgents] = useState<Agent[]>([]);
  const [wsStatus, setWsStatus] = useState<WsStatus>('connecting');
  const [aQuery,   setAQuery] = useState('');
  const [completions, setCompletions] = useState<string[]>([]);

  const bottomRef = useRef<HTMLDivElement>(null);
  const inputRef  = useRef<HTMLInputElement>(null);
  const wsRef     = useRef<WebSocket | null>(null);

  /* WebSocket */
  useEffect(() => {
    const ws = new WebSocket(shellWsUrl());
    wsRef.current = ws;
    setWsStatus('connecting');
    ws.onopen    = () => {
      setWsStatus('connected');
      setLines(p => [...p, { type:'ok', text:'[+] WebSocket shell connected', time:ts() }]);
    };
    ws.onmessage = (e) => {
      const raw   = stripAnsi(e.data as string);
      const parts = raw.split('\n').filter(s => s.length > 0);
      if (!parts.length) return;
      const now = ts();
      setLines(p => [...p, ...parts.map(text => ({ type:'ok' as const, text, time:now }))]);
    };
    ws.onerror = () => {
      setWsStatus('error');
      setLines(p => [...p, { type:'err', text:'[-] WebSocket connection failed', time:ts() }]);
    };
    ws.onclose = () => {
      setWsStatus('closed');
      setLines(p => [...p, { type:'sys', text:'[*] Shell disconnected', time:ts() }]);
    };
    return () => { ws.close(); };
  }, []);

  /* Load agents */
  useEffect(() => {
    agentsApi.list()
      .then(list => {
        const mapped = list.map(toAgent);
        _agents = mapped;
        setAgents(mapped);
        setLines(p => [...p, {
          type:'ok',
          text:`[+] ${mapped.filter(a=>a.status==='ONLINE').length} agents online / ${mapped.length} total`,
          time:ts(),
        }]);
      })
      .catch(() => setLines(p => [...p, { type:'err', text:'[-] Failed to fetch agent list', time:ts() }]));
  }, []);

  useEffect(() => { bottomRef.current?.scrollIntoView({ behavior:'smooth' }); }, [lines]);

  /* Tab autocomplete */
  const handleTab = useCallback(() => {
    const word = input.split(' ')[0].toLowerCase();
    if (!word) return;
    const matches = CMD_COMPLETIONS.filter(c => c.startsWith(word) && c !== word);
    if (matches.length === 1) {
      setInput(matches[0] + ' ');
      setCompletions([]);
    } else if (matches.length > 1) {
      setCompletions(matches);
    }
  }, [input]);

  /* Execute command */
  const exec = useCallback((raw: string) => {
    const cmd = raw.trim();
    if (!cmd) return;
    setCompletions([]);
    const time = ts();
    const out: Line[] = [{ type:'cmd', text:`ZK> ${cmd}`, time }];

    if (cmd === 'clear') {
      setLines([]);
      setHist(p => [cmd, ...p.slice(0, 99)]);
      setHIdx(-1);
      return;
    }
    if (cmd === 'exit') {
      out.push({ type:'sys', text:'[*] Shell closed.', time });
      setLines(p => [...p, ...out]);
      return;
    }

    const parts   = cmd.split(' ');
    const base    = parts[0];
    const args    = parts.slice(1);
    const handler = COMMANDS[cmd] || COMMANDS[base];

    if (handler) {
      out.push(...handler(args));
    } else if (base === 'info') {
      const id = parts[1]?.toUpperCase();
      const ag = _agents.find(a => a.id === id);
      if (ag) {
        out.push(
          { type:'sys', text:`[*] Agent info: ${ag.id}`, time },
          { type:'ok',  text:`  Status   : ${ag.status}`, time },
          { type:'info',text:`  IP       : ${ag.ip}`, time },
          { type:'info',text:`  Hostname : ${ag.hostname}`, time },
          { type:'info',text:`  OS       : ${ag.os}`, time },
          { type:'info',text:`  User     : ${ag.user} [${ag.priv}]`, time },
          { type:'info',text:`  Process  : ${ag.process} (PID ${ag.pid})`, time },
          { type:'info',text:`  Arch     : ${ag.arch}`, time },
          { type:'info',text:`  Last seen: ${ag.lastSeen}`, time },
        );
      } else if (!id) {
        out.push({ type:'sys', text:'[*] C2 Server — local bash session', time });
        out.push({ type:'info',text:'  Host: localhost:8080', time });
      } else {
        out.push({ type:'err', text:`[-] Agent not found: ${id}`, time });
      }
    } else if (base === 'sleep') {
      out.push({ type:'ok',  text:`[+] Beacon updated: ${parts[2]||'?'}s / ${parts[3]||'?'}% jitter`, time });
      out.push({ type:'sys', text:'[*] (stub — wire to PUT /api/agent/{id}/config)', time });
    } else if (base === 'kill') {
      out.push({ type:'warn', text:`[!] Sending kill signal to ${parts[1]}...`, time });
      out.push({ type:'err',  text:'[-] Agent terminated.', time });
      out.push({ type:'sys',  text:'[*] (stub — wire to POST /api/agent/{id}/kill)', time });
    } else if (base === 'interact') {
      out.push({ type:'warn', text:'[!] Use the Agents tab — double-click the agent row to open a dedicated shell.', time });
    } else if (base === 'kick') {
      out.push({ type:'ok', text:`[+] Operator ${parts[1]} disconnected.`, time });
    } else if (base === 'rename') {
      out.push({ type:'ok', text:'[+] Agent renamed.', time });
    } else {
      if (wsRef.current?.readyState === WebSocket.OPEN) {
        out.push({ type:'sys', text:`$ ${cmd}`, time });
        wsRef.current.send(cmd + '\n');
      } else {
        out.push({ type:'err', text:`[-] Unknown: "${cmd}"  —  type "help"`, time });
      }
    }

    setLines(p => [...p, ...out]);
    setHist(p => [cmd, ...p.slice(0, 99)]);
    setHIdx(-1);
  }, []);

  const wsColor = wsStatus === 'connected' ? 'var(--green)' : wsStatus === 'connecting' ? 'var(--orange)' : 'var(--red)';
  const wsLabel = wsStatus === 'connected' ? 'LIVE' : wsStatus === 'connecting' ? 'CONNECTING' : wsStatus === 'error' ? 'ERROR' : 'CLOSED';

  const filteredAgents = aQuery
    ? agents.filter(a =>
        a.id.toLowerCase().includes(aQuery.toLowerCase()) ||
        a.ip.includes(aQuery) ||
        (a.hostname||'').toLowerCase().includes(aQuery.toLowerCase())
      )
    : agents;

  const LOG_COLORS: Record<string, string> = {
    ok: 'var(--green)', err: 'var(--red)', warn: 'var(--orange)', sys: 'var(--tx2)',
  };
  const LOG_ICONS: Record<string, string> = { ok:'[+]', err:'[-]', warn:'[!]', sys:'[*]' };

  return (
    <div style={{ display:'flex', height:'100%', overflow:'hidden', fontFamily:'Courier New' }}>

      {/* ── SIDEBAR ── */}
      <div style={{ width:220, background:'var(--panel)', borderRight:'1px solid var(--b1)', display:'flex', flexDirection:'column', overflow:'hidden', flexShrink:0 }}>

        {/* Panel header with WS status */}
        <div style={{ height:24, background:'var(--panel2)', borderBottom:'1px solid var(--b1)', display:'flex', alignItems:'center', padding:'0 10px', gap:6, fontSize:10, color:'var(--tx1)', userSelect:'none', flexShrink:0 }}>
          <span style={{ color:'var(--red)', fontSize:9 }}>$_</span>
          <span>C2 Shell</span>
          <span style={{ marginLeft:'auto', display:'flex', alignItems:'center', gap:4 }}>
            <span style={{ width:5, height:5, borderRadius:'50%', background:wsColor, display:'inline-block', boxShadow:`0 0 4px ${wsColor}` }} />
            <span style={{ fontSize:9, color:wsColor }}>{wsLabel}</span>
          </span>
        </div>

        {/* Service status */}
        <div style={{ padding:'8px 10px', borderBottom:'1px solid var(--b1)', flexShrink:0 }}>
          <div style={{ fontSize:9, color:'var(--tx3)', textTransform:'uppercase', letterSpacing:1, marginBottom:6 }}>Services</div>
          {[
            { l:'C2 Server',   v:'ONLINE',  c:'var(--green)' },
            { l:'Database',    v:'CONN',    c:'var(--green)' },
            { l:'HTTP :4444',  v:'LISTEN',  c:'var(--green)' },
            { l:'HTTPS :8443', v:'LISTEN',  c:'var(--green)' },
            { l:'DNS :53',     v:'OFFLINE', c:'var(--red)'   },
          ].map(s => (
            <div key={s.l} style={{ display:'flex', justifyContent:'space-between', marginBottom:3 }}>
              <span style={{ fontSize:10, color:'var(--tx2)' }}>{s.l}</span>
              <span style={{ fontSize:10, color:s.c, fontWeight:600 }}>{s.v}</span>
            </div>
          ))}
        </div>

        {/* Agent filter + list */}
        <div style={{ padding:'5px 8px 4px', borderBottom:'1px solid var(--b1)', flexShrink:0 }}>
          <div style={{ display:'flex', justifyContent:'space-between', marginBottom:4 }}>
            <span style={{ fontSize:9, color:'var(--tx3)', textTransform:'uppercase', letterSpacing:1 }}>Agents</span>
            <span style={{ fontSize:9, color:'var(--tx3)' }}>
              <span style={{ color:'var(--green)' }}>{agents.filter(a=>a.status==='ONLINE').length}</span>
              <span>/{agents.length}</span>
            </span>
          </div>
          <input
            value={aQuery}
            onChange={e => setAQuery(e.target.value)}
            placeholder="filter..."
            style={{ width:'100%', background:'var(--inset)', border:'1px solid var(--b2)', color:'var(--tx1)', fontSize:10, padding:'2px 6px', outline:'none', boxSizing:'border-box' }}
          />
        </div>

        <div style={{ flex:1, overflowY:'auto' }}>
          {filteredAgents.map(a => {
            const sc = a.status==='ONLINE' ? 'var(--green)' : a.status==='IDLE' ? 'var(--orange)' : 'var(--tx3)';
            return (
              <div key={a.id}
                onClick={() => { setInput(`info ${a.id}`); inputRef.current?.focus(); }}
                style={{ padding:'5px 10px', borderBottom:'1px solid var(--b1)', cursor:'pointer' }}
                onMouseEnter={e => (e.currentTarget.style.background = 'var(--inset)')}
                onMouseLeave={e => (e.currentTarget.style.background = 'transparent')}
              >
                <div style={{ display:'flex', alignItems:'center', gap:5 }}>
                  <span style={{ width:5, height:5, borderRadius:'50%', background:sc, flexShrink:0, boxShadow:a.status==='ONLINE'?`0 0 4px ${sc}`:'none' }} />
                  <span style={{ fontSize:10, color:'var(--tx1)', flex:1, overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap' }}>{a.id}</span>
                  <span style={{ fontSize:9, color:a.priv==='ROOT'?'var(--red-hi)':'var(--tx3)' }}>{a.priv}</span>
                </div>
                <div style={{ fontSize:9, color:'var(--tx2)', marginLeft:10, marginTop:1 }}>{a.ip}</div>
              </div>
            );
          })}
          {!filteredAgents.length && (
            <div style={{ padding:'10px', fontSize:10, color:'var(--tx3)', textAlign:'center' }}>
              {aQuery ? 'no match' : '[*] no agents online'}
            </div>
          )}
        </div>

        {/* Quick commands */}
        <div style={{ borderTop:'1px solid var(--b1)', padding:'6px 8px', flexShrink:0 }}>
          <div style={{ fontSize:9, color:'var(--tx3)', textTransform:'uppercase', letterSpacing:1, marginBottom:5 }}>Quick</div>
          {[
            ['agents','Sessions'],['status','C2 Status'],['listeners','Listeners'],
            ['creds','Credentials'],['loot','Loot'],['db status','DB Status'],
          ].map(([cmd, label]) => (
            <button key={cmd}
              onClick={() => { exec(cmd); inputRef.current?.focus(); }}
              style={{ display:'block', width:'100%', background:'transparent', border:'none', borderLeft:'2px solid var(--b2)', color:'var(--tx1)', fontSize:10, padding:'3px 8px', cursor:'pointer', textAlign:'left', marginBottom:2 }}
              onMouseEnter={e => { e.currentTarget.style.borderLeftColor='var(--red)'; e.currentTarget.style.color='var(--red-hi)'; }}
              onMouseLeave={e => { e.currentTarget.style.borderLeftColor='var(--b2)'; e.currentTarget.style.color='var(--tx1)'; }}
            >
              &gt; {label}
            </button>
          ))}
        </div>
      </div>

      {/* ── TERMINAL ── */}
      <div style={{ flex:1, display:'flex', flexDirection:'column', background:'#141414', overflow:'hidden' }}
        onClick={() => inputRef.current?.focus()}>

        {/* Tab bar */}
        <div style={{ display:'flex', background:'var(--panel)', borderBottom:'1px solid var(--b1)', flexShrink:0, height:28, alignItems:'stretch' }}>
          {(['shell', 'log'] as const).map(tb => (
            <div key={tb} onClick={() => setTab(tb)}
              style={{
                padding:'0 16px', display:'flex', alignItems:'center', cursor:'pointer',
                fontSize:11, textTransform:'uppercase', letterSpacing:0.5,
                color: tab===tb ? 'var(--tx0)' : 'var(--tx2)',
                borderTop: tab===tb ? '2px solid var(--red)' : '2px solid transparent',
                borderRight:'1px solid var(--b1)',
                background: tab===tb ? 'var(--bg)' : 'transparent',
              }}
            >
              {tb === 'shell' ? '$ Terminal' : '≈ Event Log'}
            </div>
          ))}
          <div style={{ marginLeft:'auto', display:'flex', alignItems:'center', padding:'0 12px', gap:8, userSelect:'none' }}>
            <span style={{ fontSize:9, color:'var(--tx3)' }}>op:</span>
            <span style={{ fontSize:9, color:'var(--red-hi)', fontWeight:700 }}>ROOT_ADMIN</span>
          </div>
        </div>

        {/* Shell tab */}
        {tab === 'shell' && (
          <>
            <div style={{ flex:1, overflowY:'auto', padding:'10px 16px', fontSize:12 }}>
              {lines.map((l, i) => (
                <div key={i} style={{ display:'flex', gap:10, lineHeight:1.65, alignItems:'baseline' }}>
                  <span style={{ color:'var(--tx3)', fontSize:10, minWidth:58, flexShrink:0, userSelect:'none' }}>{l.time}</span>
                  <span style={{ color:C[l.type]||'var(--tx1)', whiteSpace:'pre-wrap' }}>{l.text}</span>
                </div>
              ))}

              {/* Tab completion suggestions */}
              {completions.length > 0 && (
                <div style={{ display:'flex', gap:4, padding:'6px 0 2px', flexWrap:'wrap' }}>
                  {completions.map(c => (
                    <span key={c}
                      onClick={() => { setInput(c+' '); setCompletions([]); inputRef.current?.focus(); }}
                      style={{ fontSize:11, color:'var(--cyan)', background:'var(--cyan2)', padding:'1px 8px', cursor:'pointer', border:'1px solid var(--b2)' }}
                    >{c}</span>
                  ))}
                </div>
              )}
              <div ref={bottomRef} />
            </div>

            {/* Input bar */}
            <div style={{ display:'flex', alignItems:'center', gap:8, padding:'7px 16px', borderTop:'1px solid var(--b1)', background:'var(--inset)', flexShrink:0 }}>
              <span style={{ color:'var(--red-hi)', fontSize:13, fontWeight:700, userSelect:'none' }}>ZK&gt;</span>
              <input
                ref={inputRef}
                value={input}
                onChange={e => { setInput(e.target.value); setCompletions([]); }}
                autoFocus
                onKeyDown={e => {
                  if (e.key === 'Enter')     { exec(input); setInput(''); }
                  if (e.key === 'ArrowUp')   { e.preventDefault(); const ni = Math.min(histIdx+1, history.length-1); setHIdx(ni); setInput(history[ni]??''); }
                  if (e.key === 'ArrowDown') { e.preventDefault(); const ni = Math.max(histIdx-1, -1); setHIdx(ni); setInput(ni===-1?'':history[ni]??''); }
                  if (e.key === 'Tab')       { e.preventDefault(); handleTab(); }
                  if (e.key === 'Escape')    { setCompletions([]); }
                }}
                style={{ flex:1, background:'transparent', border:'none', color:'var(--tx0)', fontSize:12, outline:'none' }}
                placeholder='command...  (help | Tab = autocomplete | ↑↓ = history)'
              />
              <div style={{ display:'flex', alignItems:'center', gap:4, userSelect:'none' }}>
                <span style={{ width:5, height:5, borderRadius:'50%', background:wsColor, boxShadow:`0 0 4px ${wsColor}`, flexShrink:0 }} />
                <span style={{ fontSize:9, color:wsColor }}>{wsLabel}</span>
              </div>
            </div>
          </>
        )}

        {/* Event Log tab */}
        {tab === 'log' && (
          <div style={{ flex:1, overflowY:'auto', padding:'10px 16px', fontSize:11 }}>
            <div style={{ marginBottom:10, fontSize:9, color:'var(--tx3)', textTransform:'uppercase', letterSpacing:1 }}>C2 Event Log</div>
            {LOG_EVENTS.map((e, i) => (
              <div key={i} style={{ display:'flex', gap:10, padding:'4px 0', borderBottom:'1px solid var(--b1)', alignItems:'baseline' }}>
                <span style={{ color:'var(--tx3)', minWidth:58, flexShrink:0, userSelect:'none' }}>{e.t}</span>
                <span style={{ color:LOG_COLORS[e.c], minWidth:28, flexShrink:0 }}>{LOG_ICONS[e.c]}</span>
                <span style={{ color:'var(--tx1)' }}>{e.m}</span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
