'use client';
import { useState, useRef, useEffect } from 'react';
import { Agent } from '@/lib/models/agents/agentModel';
import { agentsApi, toAgent } from '@/lib/client/api';

const stripAnsi = (s: string) =>
  s.replace(/\x1B\[[0-9;]*[A-Za-z]/g, '').replace(/\r\n/g, '\n').replace(/\r/g, '\n');

// Module-level cache so COMMANDS closures can access live agent data
let _agents: Agent[] = [];

interface Line { type: string; text: string; time: string; }

const t = () => {
  const d = new Date();
  return `${d.getHours().toString().padStart(2,'0')}:${d.getMinutes().toString().padStart(2,'0')}:${d.getSeconds().toString().padStart(2,'0')}`;
};

const C: Record<string, string> = {
  cmd: '#cccccc', ok: '#33a84a', err: '#e05c6e',
  warn: '#d48b55', sys: '#444', info: '#5bb8d4', dim: '#2a2a2a',
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
  help:      () => HELP_TEXT.split('\n').map(l => ({
    type: l.startsWith('[*]') ? 'ok' : l.startsWith('───') ? 'dim' : l.match(/^[A-Z]/) ? 'warn' : l.startsWith('  ') ? 'info' : 'sys',
    text: l, time: t(),
  })),

  agents: () => [
    { type:'sys', text:'[*] Active sessions:', time:t() },
    ..._agents.map(a => ({
      type: a.status === 'ONLINE' ? 'ok' : a.status === 'IDLE' ? 'warn' : 'err',
      text: `  ${a.id.padEnd(8)} ${a.ip.padEnd(16)} ${a.status.padEnd(8)} ${a.user.padEnd(12)} [${a.priv}]  ${a.os}  (${a.lastSeen})`,
      time: t(),
    })),
    { type:'sys', text:`[*] Total: ${_agents.length} | Online: ${_agents.filter(a=>a.status==='ONLINE').length} | Idle: ${_agents.filter(a=>a.status==='IDLE').length} | Lost: ${_agents.filter(a=>a.status==='LOST').length}`, time:t() },
  ],

  sessions: () => COMMANDS.agents([]),

  listeners: () => [
    { type:'sys', text:'[*] Active listeners:', time:t() },
    { type:'ok',  text:'  [1]  HTTP   0.0.0.0:4444   ONLINE  agents:4', time:t() },
    { type:'ok',  text:'  [2]  HTTPS  0.0.0.0:8443   ONLINE  agents:2', time:t() },
    { type:'err', text:'  [3]  DNS    0.0.0.0:53     OFFLINE agents:0', time:t() },
  ],

  status: () => [
    { type:'sys',  text:'[*] C2 Server Status', time:t() },
    { type:'ok',   text:'  Framework   : ZOMBIE_KEEPER v3.0.1', time:t() },
    { type:'ok',   text:'  Status      : ONLINE', time:t() },
    { type:'ok',   text:'  Uptime      : 04:22:11', time:t() },
    { type:'ok',   text:'  Database    : CONNECTED (mysql://localhost:3306)', time:t() },
    { type:'ok',   text:'  Listeners   : 2 online / 3 total', time:t() },
    { type:'ok',   text:'  Agents      : 4 online / 6 total', time:t() },
    { type:'info', text:'  Threads     : 14 active', time:t() },
    { type:'info', text:'  Memory      : 512 MB / 8192 MB', time:t() },
    { type:'warn', text:'  CPU Load    : 87% [HIGH]', time:t() },
    { type:'ok',   text:'  Disk Free   : 22 GB', time:t() },
  ],

  config: () => [
    { type:'sys', text:'[*] Current C2 Configuration', time:t() },
    { type:'info',text:'  listener.host    = 0.0.0.0', time:t() },
    { type:'info',text:'  listener.port    = 4444', time:t() },
    { type:'info',text:'  beacon.interval  = 10s', time:t() },
    { type:'info',text:'  beacon.jitter    = 23%', time:t() },
    { type:'info',text:'  auth.mode        = JWT + JSESSIONID', time:t() },
    { type:'info',text:'  db.host          = localhost:3306', time:t() },
    { type:'info',text:'  db.name          = zombie_keeper_db', time:t() },
    { type:'info',text:'  log.level        = INFO', time:t() },
    { type:'info',text:'  rbac.enabled     = true', time:t() },
  ],

  creds: () => [
    { type:'sys',  text:'[*] Collected credentials:', time:t() },
    { type:'ok',   text:'  [1] root:$6$hash... (linux/shadow) — ZK-001', time:t() },
    { type:'ok',   text:'  [2] admin:Password1! (plaintext/env) — ZK-003', time:t() },
    { type:'warn', text:'  [3] svc_acct:hash... (linux/shadow) — ZK-003', time:t() },
    { type:'ok',   text:'  [4] AWS_ACCESS_KEY_ID=AKIA... — ZK-003', time:t() },
    { type:'sys',  text:'[*] 4 credentials. Use "creds export" to dump CSV.', time:t() },
  ],

  loot: () => [
    { type:'sys', text:'[*] Loot files:', time:t() },
    { type:'ok',  text:'  [1] /etc/passwd     (ZK-001)  2.1 KB  2024-01-15', time:t() },
    { type:'ok',  text:'  [2] /etc/shadow     (ZK-001)  1.8 KB  2024-01-15', time:t() },
    { type:'ok',  text:'  [3] id_rsa          (ZK-001)  1.7 KB  2024-01-15', time:t() },
    { type:'ok',  text:'  [4] passwords.txt   (ZK-001)  512 B   2024-01-15', time:t() },
    { type:'warn',text:'  [5] screen_001.png  (ZK-002)  847 KB  2024-01-15', time:t() },
  ],

  operators: () => [
    { type:'sys', text:'[*] Connected operators:', time:t() },
    { type:'ok',  text:'  ROOT_ADMIN  [you]  ADMIN   connected 04:22:11', time:t() },
    { type:'info',text:'  op_ghost           OPERATOR connected 00:14:33', time:t() },
  ],

  'db': (args) => {
    if (args[0] === 'status') return [
      { type:'ok',  text:'[+] Database: CONNECTED', time:t() },
      { type:'info',text:'  Host    : localhost:3306', time:t() },
      { type:'info',text:'  Schema  : zombie_keeper_db', time:t() },
      { type:'info',text:'  Pool    : 10/10 connections', time:t() },
    ];
    if (args[0] === 'backup') return [
      { type:'sys', text:'[*] Triggering database backup...', time:t() },
      { type:'ok',  text:'[+] Backup complete: /backups/zk_2024-01-15_042211.sql.gz', time:t() },
    ];
    if (args[0] === 'stats') return [
      { type:'sys', text:'[*] Database statistics:', time:t() },
      { type:'info',text:'  Agents      : 6 records', time:t() },
      { type:'info',text:'  Sessions    : 142 total', time:t() },
      { type:'info',text:'  Credentials : 4 collected', time:t() },
      { type:'info',text:'  Loot files  : 5 items', time:t() },
      { type:'info',text:'  Events      : 2,341 log entries', time:t() },
    ];
    return [{ type:'err', text:'[-] Usage: db <status|backup|stats>', time:t() }];
  },

  reload: () => [
    { type:'sys', text:'[*] Reloading C2 configuration...', time:t() },
    { type:'ok',  text:'[+] Configuration reloaded. No restart required.', time:t() },
  ],

  payload: (args) => {
    if (args[0] === 'list') return [
      { type:'sys',  text:'[*] Generated payloads:', time:t() },
      { type:'ok',   text:'  [1] windows_x64.exe   HTTP/4444  2024-01-15  47.2 KB', time:t() },
      { type:'info', text:'  [2] linux_x64.elf      HTTP/4444  2024-01-14  38.1 KB', time:t() },
    ];
    if (args[0] === 'gen')    return [{ type:'warn', text:'[!] Use the Payload Generator UI (Payloads tab)', time:t() }];
    return [{ type:'err', text:'[-] Usage: payload <list|gen|stager <id>>', time:t() }];
  },

  shutdown: () => [
    { type:'warn', text:'[!] WARNING: This will stop the C2 server.', time:t() },
    { type:'warn', text:'[!] Type "shutdown confirm" to proceed.', time:t() },
  ],

  'shutdown confirm': () => [
    { type:'err', text:'[-] Initiating graceful shutdown...', time:t() },
    { type:'err', text:'[-] All agent sessions will be disconnected.', time:t() },
    { type:'sys', text:'[*] (stub — wire to POST /api/c2/shutdown)', time:t() },
  ],
};

//TODO: implmentar melhorias no shell, como interação com o nano, vim, info, alguns comandos estao quebrando a sesão
export default function ShellModule() {
  const [lines,   setLines]  = useState<Line[]>([
    { type:'sys', text:'ZOMBIE KEEPER C2 — Interactive Operator Shell', time:t() },
    { type:'sys', text:'─────────────────────────────────────────────', time:t() },
    { type:'ok',  text:`[+] Authenticated as ROOT_ADMIN (ADMIN)`, time:t() },
    { type:'info',text:'[*] Type "help" for command reference', time:t() },
  ]);
  const [input,   setInput]  = useState('');
  const [history, setHist]   = useState<string[]>([]);
  const [histIdx, setHIdx]   = useState(-1);
  const [tab,     setTab]    = useState<'shell'|'log'>('shell');
  const [agents,  setAgents] = useState<Agent[]>([]);
  const bottomRef            = useRef<HTMLDivElement>(null);
  const inputRef             = useRef<HTMLInputElement>(null);
  //TODO: Criar um arquivo apenas pro websocket, pra não misturar lógica de WS com a UI do shell. O ref e os handlers de WS poderiam ficar lá, e o ShellModule só chamaria funções tipo ws.sendCommand(cmd) e ws.onOutput(callback).
  // useRef guarda a instância do WebSocket sem causar re-render quando muda.
  // Se fosse useState, cada update recriaria o componente e abriria uma nova conexão.
  const wsRef = useRef<WebSocket | null>(null);

  useEffect(() => {
    // O proxy /api/shell lê o cookie httpOnly e conecta ao Spring Boot com o token.
    // Sem token visível no browser, sem URL do Spring Boot exposta.
    const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const ws = new WebSocket(`${proto}//${window.location.host}/api/shell`);

    // Salva a instância no ref para poder usar em outros lugares do componente (ex: enviar comandos)
    wsRef.current = ws;

    // Disparado quando a conexão é estabelecida com sucesso.
    // Neste momento o backend já abriu um processo bash e está lendo o stdout.
    ws.onopen = () => {
      setLines(prev => [...prev, { type: 'ok', text: '[+] Shell connected (bash)', time: t() }]);
    };

    // Disparado toda vez que o backend manda dados — ou seja, sempre que o bash imprime algo.
    // e.data é uma string com o chunk de saída do bash (pode ter múltiplas linhas).
    ws.onmessage = (e) => {
      // Remove códigos ANSI de cor/cursor que o bash injeta (ex: \x1B[32m)
      const raw = stripAnsi(e.data as string);
      // Divide em linhas e filtra vazias para exibir cada linha separada no terminal
      const parts = raw.split('\n').filter(s => s.length > 0);
      if (!parts.length) return;
      const ts = t();
      setLines(prev => [...prev, ...parts.map(text => ({ type: 'ok' as const, text, time: ts }))]);
    };

    // Disparado se houver falha de rede ou o backend rejeitar a conexão (ex: token inválido)
    ws.onerror = () => {
      setLines(prev => [...prev, { type: 'err', text: '[-] WebSocket error', time: t() }]);
    };

    // Disparado quando a conexão é fechada — seja pelo backend, pelo browser, ou pelo ws.close()
    ws.onclose = () => {
      setLines(prev => [...prev, { type: 'sys', text: '[*] Shell disconnected', time: t() }]);
    };

    // Cleanup: quando o componente é desmontado, fecha a conexão para não deixar o bash órfão no servidor
    return () => { ws.close(); };
  }, []); // [] = roda só uma vez ao montar o componente

  useEffect(() => {
    agentsApi.list()
      .then(list => {
        const mapped = list.map(toAgent);
        _agents = mapped;
        setAgents(mapped);
        setLines(prev => [...prev, {
          type: 'ok',
          text: `[+] ${mapped.filter(a => a.status === 'ONLINE').length} agents online / ${mapped.length} total`,
          time: t(),
        }]);
      })
      .catch(() => setLines(prev => [...prev, { type:'err', text:'[-] Failed to fetch agent list', time:t() }]));
  }, []);

  useEffect(() => { bottomRef.current?.scrollIntoView({ behavior: 'smooth' }); }, [lines]);

  const exec = (raw: string) => {
    const cmd = raw.trim(); if (!cmd) return;
    const time = t();
    const out: Line[] = [{ type: 'cmd', text: `ZK> ${cmd}`, time }];

    if (cmd === 'clear') { setLines([]); return; }
    if (cmd === 'exit')  { out.push({ type:'sys', text:'[*] Shell closed.', time }); setLines(p => [...p, ...out]); return; }

    // Find handler
    const parts  = cmd.split(' ');
    const base   = parts[0];
    const args   = parts.slice(1);
    const handler = COMMANDS[cmd] || COMMANDS[base];

    if (handler) {
      out.push(...handler(args));
    } else if (cmd.startsWith('info')) {
      const id  = cmd.split(' ')[1]?.toUpperCase();
      const ag  = _agents.find(a => a.id === id);
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
        //TODO: agent undefined mas  shell aberto (Shell do servidor), TODO: Criar shell.isOpen para diferenciar shell do servidor de shell de agente, e não mostrar info de agente quando for shell do servidor
      }else if(ag == undefined  ){
        out.push(
          { type:'sys', text:`[*] Agent info: ${"C2-SERVER"}`, time },
          { type:'ok',  text:`  Status   : ${"ONLINE"}`, time },
          { type:'info',text:`  IP       : ${"127.0.0.1"}`, time },
          { type:'info',text:`  Hostname : ${"C2-SERVER"}`, time },
          { type:'info',text:`  OS       : ${"Linux"}`, time },
          { type:'info',text:`  User     : ${"root"} [${"root"}]`, time },
          { type:'info',text:`  Process  : ${"zombiekeeper"} (PID ${"1234"})`, time },
          { type:'info',text:`  Arch     : ${"x86_64"}`, time },
          { type:'info',text:`  Last seen: ${"Never"}`, time },
        );
      }
      else {
        out.push({ type:'err', text:`[-] Agent not found: ${id}`, time });
      }
    } else if (cmd.startsWith('sleep ')) {
      const parts2 = cmd.split(' ');
      out.push({ type:'ok', text:`[+] Beacon updated: ${parts2[2] || '?'}s / ${parts2[3] || '?'}% jitter`, time });
      out.push({ type:'sys', text:'[*] (stub — wire to PUT /api/agent/{id}/config)', time });
    } else if (cmd.startsWith('kill ')) {
      out.push({ type:'warn', text:`[!] Sending kill signal to ${cmd.split(' ')[1]}...`, time });
      out.push({ type:'err',  text:'[-] Agent terminated.', time });
      out.push({ type:'sys',  text:'[*] (stub — wire to POST /api/agent/{id}/kill)', time });
    } else if (cmd.startsWith('interact ')) {
      out.push({ type:'warn', text:`[!] Use the Agents tab — double-click the agent row to open a dedicated shell.`, time });
    } else if (cmd.startsWith('kick ')) {
      out.push({ type:'ok', text:`[+] Operator ${cmd.split(' ')[1]} disconnected.`, time });
    } else if (cmd.startsWith('rename ')) {
      out.push({ type:'ok', text:`[+] Agent renamed.`, time });
    } else {
      // Comando não reconhecido como C2 — tenta mandar pro bash via WebSocket.
      // readyState === WebSocket.OPEN (valor 1) significa que a conexão está ativa.
      if (wsRef.current?.readyState === WebSocket.OPEN) {
        out.push({ type:'sys', text:`$ ${cmd}`, time });
        // Envia o comando com "\n" no final — equivale a pressionar Enter no bash
        wsRef.current.send(cmd + '\n');
        // A resposta NÃO vem aqui — ela chega de forma assíncrona no ws.onmessage acima
      } else {
        out.push({ type:'err', text:`[-] Unknown command: "${cmd}"  —  type "help"`, time });
      }
    }

    setLines(p => [...p, ...out]);
    setHist(p => [cmd, ...p.slice(0, 99)]);
    setHIdx(-1);
  };

  return (
    <div style={{ display: 'flex', height: '100%', overflow: 'hidden' }}>

      {/* ── SIDEBAR: C2 status snapshot ── */}
      <div style={{ width: 220, background: '#0d0d0d', borderRight: '1px solid #1a1a1a', display: 'flex', flexDirection: 'column', overflow: 'hidden', flexShrink: 0 }}>
        <div style={{ padding: '5px 10px', background: '#111', borderBottom: '1px solid #1a1a1a', fontSize: 10, color: '#444', textTransform: 'uppercase', letterSpacing: 1 }}>
          C2 Status
        </div>

        {/* Status indicators */}
        <div style={{ padding: '10px 12px', borderBottom: '1px solid #111' }}>
          {[
            { l: 'C2 Server',   v: 'ONLINE',     c: '#33a84a' },
            { l: 'Database',    v: 'CONNECTED',   c: '#33a84a' },
            { l: 'HTTP :4444',  v: 'LISTENING',   c: '#33a84a' },
            { l: 'HTTPS :8443', v: 'LISTENING',   c: '#33a84a' },
            { l: 'DNS :53',     v: 'OFFLINE',     c: '#e05c6e' },
          ].map(s => (
            <div key={s.l} style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 5 }}>
              <span style={{ fontSize: 10, color: '#444', fontFamily: 'Courier New' }}>{s.l}</span>
              <span style={{ fontSize: 10, color: s.c, fontFamily: 'Courier New' }}>{s.v}</span>
            </div>
          ))}
        </div>

        {/* Agent quick list */}
        <div style={{ padding: '5px 10px', background: '#0a0a0a', borderBottom: '1px solid #111', fontSize: 9, color: '#2a2a2a', textTransform: 'uppercase', letterSpacing: 1 }}>
          Agents
        </div>
        <div style={{ flex: 1, overflowY: 'auto' }}>
          {agents.map(a => (
            <div key={a.id}
              onClick={() => { setInput(`info ${a.id}`); inputRef.current?.focus(); }}
              style={{ padding: '6px 12px', borderBottom: '1px solid #0d0d0d', cursor: 'pointer' }}
              onMouseEnter={e => (e.currentTarget.style.background = '#111')}
              onMouseLeave={e => (e.currentTarget.style.background = 'transparent')}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                <span style={{ width: 5, height: 5, borderRadius: '50%', background: a.status === 'ONLINE' ? '#33a84a' : a.status === 'IDLE' ? '#d48b55' : '#444', flexShrink: 0 }} />
                <span style={{ fontSize: 10, color: '#888', fontFamily: 'Courier New' }}>{a.id}</span>
                <span style={{ marginLeft: 'auto', fontSize: 9, color: a.priv === 'ROOT' ? '#e05c6e' : '#333', fontFamily: 'Courier New' }}>{a.priv}</span>
              </div>
              <div style={{ fontSize: 9, color: '#333', fontFamily: 'Courier New', marginLeft: 11 }}>{a.ip}</div>
            </div>
          ))}
        </div>

        {/* Quick commands */}
        <div style={{ padding: '5px 10px', background: '#0a0a0a', borderTop: '1px solid #111', borderBottom: '1px solid #111', fontSize: 9, color: '#2a2a2a', textTransform: 'uppercase', letterSpacing: 1 }}>
          Quick Commands
        </div>
        <div style={{ padding: '8px 10px', flexShrink: 0 }}>
          {[['agents','List sessions'],['status','C2 status'],['listeners','Listeners'],['creds','Credentials'],['loot','Loot files'],['db status','DB status']].map(([cmd, label]) => (
            <button key={cmd}
              onClick={() => { exec(cmd); inputRef.current?.focus(); }}
              style={{ display: 'block', width: '100%', background: 'transparent', border: '1px solid #111', borderLeft: '2px solid #1a1a1a', color: '#444', fontFamily: 'Courier New', fontSize: 10, padding: '4px 8px', cursor: 'pointer', textAlign: 'left', marginBottom: 3 }}
              onMouseEnter={e => { e.currentTarget.style.borderLeftColor = '#e05c6e'; e.currentTarget.style.color = '#e05c6e'; }}
              onMouseLeave={e => { e.currentTarget.style.borderLeftColor = '#1a1a1a'; e.currentTarget.style.color = '#444'; }}>
              &gt; {label}
            </button>
          ))}
        </div>
      </div>

      {/* ── TERMINAL ── */}
      <div style={{ flex: 1, display: 'flex', flexDirection: 'column', background: '#080808', overflow: 'hidden' }}
        onClick={() => inputRef.current?.focus()}>

        {/* Sub-tabs */}
        <div style={{ display: 'flex', background: '#0d0d0d', borderBottom: '1px solid #111', flexShrink: 0, height: 32, alignItems: 'stretch' }}>
          {(['shell', 'log'] as const).map(tb => (
            <div key={tb} onClick={() => setTab(tb)} style={{
              padding: '0 16px', display: 'flex', alignItems: 'center', cursor: 'pointer',
              fontSize: 11, fontFamily: 'Courier New', textTransform: 'uppercase',
              color: tab === tb ? '#cccccc' : '#333',
              borderTop: tab === tb ? '2px solid #e05c6e' : '2px solid transparent',
              borderRight: '1px solid #111',
              background: tab === tb ? '#080808' : 'transparent',
            }}>{tb === 'shell' ? 'Shell' : 'Event Log'}</div>
          ))}
          <div style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', padding: '0 12px', gap: 6 }}>
            <span style={{ fontSize: 9, color: '#2a2a2a', fontFamily: 'Courier New' }}>operator:</span>
            <span style={{ fontSize: 9, color: '#e05c6e', fontFamily: 'Courier New' }}>ROOT_ADMIN</span>
          </div>
        </div>

        {tab === 'shell' && (
          <>
            <div style={{ flex: 1, overflowY: 'auto', padding: '10px 16px', fontFamily: 'Courier New', fontSize: 12 }}>
              {lines.map((l, i) => (
                <div key={i} style={{ display: 'flex', gap: 10, lineHeight: 1.65, alignItems: 'baseline' }}>
                  <span style={{ color: '#1a1a1a', fontSize: 10, minWidth: 58, flexShrink: 0 }}>{l.time}</span>
                  <span style={{ color: C[l.type] || '#888', whiteSpace: 'pre-wrap' }}>{l.text}</span>
                </div>
              ))}
              <div ref={bottomRef} />
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '8px 16px', borderTop: '1px solid #111', background: '#0a0a0a', flexShrink: 0 }}>
              <span style={{ color: '#e05c6e', fontFamily: 'Courier New', fontSize: 12, fontWeight: 700 }}>ZK&gt;</span>
              <input ref={inputRef} value={input} onChange={e => setInput(e.target.value)} autoFocus
                onKeyDown={e => {
                  if (e.key === 'Enter')     { exec(input); setInput(''); }
                  if (e.key === 'ArrowUp')   { e.preventDefault(); const i = Math.min(histIdx+1,history.length-1); setHIdx(i); setInput(history[i]??''); }
                  if (e.key === 'ArrowDown') { e.preventDefault(); const i = Math.max(histIdx-1,-1); setHIdx(i); setInput(i===-1?'':history[i]??''); }
                  if (e.key === 'Tab')       { e.preventDefault(); /* TODO: autocomplete */ }
                }}
                style={{ flex: 1, background: 'transparent', border: 'none', color: '#cccccc', fontFamily: 'Courier New', fontSize: 12, outline: 'none' }}
                placeholder='type command (try "help")...' />
            </div>
          </>
        )}

        {tab === 'log' && (
          <div style={{ flex: 1, overflowY: 'auto', padding: '10px 16px', fontFamily: 'Courier New', fontSize: 11 }}>
            <div style={{ marginBottom: 10, color: '#2a2a2a', fontSize: 10, textTransform: 'uppercase', letterSpacing: 1 }}>C2 Event Log</div>
            {[
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
            ].map((e, i) => (
              <div key={i} style={{ display: 'flex', gap: 12, padding: '4px 0', borderBottom: '1px solid #0d0d0d' }}>
                <span style={{ color: '#222', minWidth: 58 }}>{e.t}</span>
                <span style={{ color: { ok:'#33a84a', err:'#e05c6e', warn:'#d48b55', sys:'#444' }[e.c] }}>
                  {e.c === 'ok' ? '[+]' : e.c === 'err' ? '[-]' : e.c === 'warn' ? '[!]' : '[*]'}
                </span>
                <span style={{ color: '#666' }}>{e.m}</span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
