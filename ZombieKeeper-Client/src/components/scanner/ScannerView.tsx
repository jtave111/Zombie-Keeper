import { useState, useRef, useEffect } from 'react';


interface ScanLine { tag: string; cls: string; time: string; msg: string; }

const now = () => {
  const d = new Date();
  return `${d.getHours().toString().padStart(2,'0')}:${d.getMinutes().toString().padStart(2,'0')}:${d.getSeconds().toString().padStart(2,'0')}`;
};

const SCAN_TYPES = [
  { key:'tcp',    label:'TCP SYN',       desc:'Half-open SYN scan — stealth' },
  { key:'udp',    label:'UDP',           desc:'UDP port discovery' },
  { key:'full',   label:'Full Connect',  desc:'Complete 3-way handshake' },
  { key:'os',     label:'OS Detect',     desc:'OS fingerprinting via TTL/TCP stack' },
  { key:'svc',    label:'Svc Probe',     desc:'Service/version banner grabbing' },
  { key:'vuln',   label:'Vuln Scan',     desc:'Port banner → CVE matching' },
  { key:'arp',    label:'ARP Sweep',     desc:'Layer 2 host discovery' },
  { key:'icmp',   label:'ICMP Ping',     desc:'ICMP echo host discovery' },
  { key:'dns',    label:'DNS Brute',     desc:'DNS hostname enumeration' },
  { key:'ssh',    label:'SSH Audit',     desc:'SSH ciphers/hostkey audit' },
  { key:'http',   label:'HTTP Probe',    desc:'HTTP/HTTPS fingerprint + headers' },
  { key:'smb',    label:'SMB Audit',     desc:'SMB version, shares, signing' },
];

const PORT_SCOPES = [
  { key:'common',  label:'Common',       range:'top 1000 ports' },
  { key:'full',    label:'Full 0–65535', range:'all 65535 ports' },
  { key:'web',     label:'Web',          range:'80,443,8080,8443,8888,3000' },
  { key:'db',      label:'Databases',    range:'3306,5432,1433,1521,27017,6379' },
  { key:'vuln',    label:'Risk Ports',   range:'22,23,445,3389,5900,21,25' },
  { key:'custom',  label:'Custom',       range:'enter manually' },
];

function generateScanLog(target: string, types: string[], scope: string, aggr: string, targetNode?: string): ScanLine[] {
  const lines: ScanLine[] = [];
  const t = now();
  const isSingle = !!targetNode;
  const targetIp = targetNode ?? '';

  lines.push({ tag:'SYS', cls:'sys', time:t, msg:`Initializing scanner engine...` });
  lines.push({ tag:'SYS', cls:'sys', time:t, msg:`Target: ${isSingle ? targetIp : target} | Types: ${types.join(',')} | Scope: ${scope} | Mode: ${aggr}` });
  
  if (types.includes('arp')) {
    lines.push({ tag:'SYS',  cls:'sys',  time:t, msg:`ARP sweep ${target}...` });
    lines.push({ tag:'OK',   cls:'ok',   time:t, msg:`192.168.1.1   aa:bb:cc:00:00:01  TP-Link Technologies` });
    lines.push({ tag:'OK',   cls:'ok',   time:t, msg:`192.168.1.42  aa:bb:cc:dd:ee:02  Dell Inc.` });
    lines.push({ tag:'OK',   cls:'ok',   time:t, msg:`192.168.1.99  aa:bb:cc:dd:ee:03  Unknown vendor` });
    lines.push({ tag:'OK',   cls:'ok',   time:t, msg:`192.168.1.55  aa:bb:cc:dd:ee:04  Apple Inc.` });
    lines.push({ tag:'OK',   cls:'ok',   time:t, msg:`192.168.1.200 aa:bb:cc:dd:ee:05  Unknown vendor [!] NEW` });
    lines.push({ tag:'SYS',  cls:'sys',  time:t, msg:`ARP complete: 5 hosts responded` });
  }

  if (types.includes('tcp') || types.includes('full')) {
    const scanT = isSingle ? targetIp! : '192.168.1.1';
    lines.push({ tag:'SYS',  cls:'sys',  time:t, msg:`TCP scan ${isSingle?targetIp:target}...` });
    lines.push({ tag:'FIND', cls:'find', time:t, msg:`${scanT}  port 22/tcp    open  ssh     SSH-2.0-OpenSSH_8.9p1` });
    lines.push({ tag:'FIND', cls:'find', time:t, msg:`${scanT}  port 80/tcp    open  http    Apache/2.4.52 (Ubuntu)` });
    lines.push({ tag:'FIND', cls:'find', time:t, msg:`${scanT}  port 443/tcp   open  https   Apache/2.4.52 TLS1.3` });
    if (!isSingle) {
      lines.push({ tag:'FIND', cls:'find', time:t, msg:`192.168.1.42  port 22/tcp    open  ssh     SSH-2.0-OpenSSH_8.9p1` });
      lines.push({ tag:'FIND', cls:'find', time:t, msg:`192.168.1.42  port 3306/tcp  open  mysql   5.5.5-10.6.12-MariaDB` });
      lines.push({ tag:'WARN', cls:'warn', time:t, msg:`192.168.1.42  port 3306/tcp  — MySQL exposed to network [RISK]` });
      lines.push({ tag:'FIND', cls:'find', time:t, msg:`192.168.1.99  port 445/tcp   open  smb     Windows SMB 3.1.1` });
      lines.push({ tag:'ERR',  cls:'err',  time:t, msg:`192.168.1.99  port 445/tcp   — SMB exposed, untrusted host [CRITICAL]` });
      lines.push({ tag:'ERR',  cls:'err',  time:t, msg:`192.168.1.99  port 3389/tcp  — RDP exposed, brute-force surface [HIGH]` });
      lines.push({ tag:'ERR',  cls:'err',  time:t, msg:`192.168.1.200 port 3389/tcp  — Unknown host, RDP open [CRITICAL]` });
    }
  }

  if (types.includes('os')) {
    const scanT = isSingle ? targetIp! : '192.168.1.1';
    lines.push({ tag:'SYS',  cls:'sys',  time:t, msg:`OS fingerprinting...` });
    lines.push({ tag:'OK',   cls:'ok',   time:t, msg:`${scanT}  OS: Linux 5.x (confidence 95%) — TTL=64, window=65535` });
    if (!isSingle) lines.push({ tag:'OK', cls:'ok', time:t, msg:`192.168.1.99  OS: Windows 10/11 (confidence 92%) — TTL=128, window=8192` });
  }

  if (types.includes('svc')) {
    lines.push({ tag:'SYS', cls:'sys', time:t, msg:`Banner grabbing ${isSingle?targetIp:target}...` });
    lines.push({ tag:'OK',  cls:'ok',  time:t, msg:`Banners captured for ${isSingle?'1':0} hosts` });
  }

  if (types.includes('vuln')) {
    lines.push({ tag:'SYS',  cls:'sys',  time:t, msg:`Running vulnerability matching against banners...` });
    lines.push({ tag:'WARN', cls:'warn', time:t, msg:`CVE-2023-38408: SSH OpenSSH < 9.3 — matched 2 hosts` });
    lines.push({ tag:'ERR',  cls:'err',  time:t, msg:`CVE-2023-42794: Apache Tomcat 9.0.70 — matched 192.168.1.42:8080` });
    lines.push({ tag:'ERR',  cls:'err',  time:t, msg:`MS17-010: SMBv1 risk surface — matched 192.168.1.99:445` });
  }

  if (types.includes('ssh')) {
    lines.push({ tag:'SYS',  cls:'sys',  time:t, msg:`SSH cipher audit...` });
    lines.push({ tag:'WARN', cls:'warn', time:t, msg:`Weak cipher: diffie-hellman-group14-sha1 — 192.168.1.1:22` });
    lines.push({ tag:'OK',   cls:'ok',   time:t, msg:`192.168.1.42:22  — Ciphers acceptable` });
  }

  if (types.includes('smb')) {
    lines.push({ tag:'SYS',  cls:'sys',  time:t, msg:`SMB audit 192.168.1.99:445...` });
    lines.push({ tag:'ERR',  cls:'err',  time:t, msg:`SMB signing: DISABLED — relay attacks possible` });
    lines.push({ tag:'WARN', cls:'warn', time:t, msg:`SMB shares: IPC$, ADMIN$, C$  — admin shares exposed` });
    lines.push({ tag:'ERR',  cls:'err',  time:t, msg:`Guest access: ENABLED — unauthenticated enumeration possible` });
  }

  if (types.includes('http')) {
    lines.push({ tag:'SYS',  cls:'sys',  time:t, msg:`HTTP probe ${isSingle?targetIp:target}...` });
    lines.push({ tag:'OK',   cls:'ok',   time:t, msg:`192.168.1.1:80   Apache/2.4.52 — X-Content-Type-Options missing` });
    lines.push({ tag:'WARN', cls:'warn', time:t, msg:`192.168.1.1:80   Server header discloses version` });
  }

  if (!isSingle) {
    const hostsUp   = 0;
    const portsFound = 0;
    const risks      = 0;
    lines.push({ tag:'OK',  cls:'ok',  time:t, msg:`Scan complete — ${hostsUp} hosts up, ${portsFound} ports open, ${risks} risk ports` });
  } else {
    lines.push({ tag:'OK', cls:'ok', time:t, msg:`Single-node scan complete — ${targetIp}` });
  }

  return lines;
}

interface ScannerViewProps {
  targetNode?: import('@/lib/models/localNetwork/networkModel').NetworkNode | null;
  onClose?: () => void;
}

export default function ScannerView({ targetNode, onClose }: ScannerViewProps) {
  const nodeIp = targetNode && typeof targetNode === 'object' ? (targetNode as any).ipv4 as string : '';
  const [selectedTypes, setTypes] = useState<string[]>(['tcp','svc']);
  const [scope,    setScope]    = useState('common');
  const [aggr,     setAggr]     = useState('STEALTH');
  const [target,   setTarget]   = useState(nodeIp || '192.168.1.0/24');
  const [running,  setRunning]  = useState(false);
  const [scanMode, setScanMode] = useState<'standard'|'custom'>('standard');
  // Custom scanner state
  const [customCmd,  setCustomCmd]  = useState('nmap -sV -sC -T4 --script vuln');
  const [customTgt,  setCustomTgt]  = useState('192.168.1.0/24');
  const [customNotes,setCustomNotes]= useState('');
  const [savedScans, setSavedScans] = useState<{name:string;cmd:string;tgt:string;notes:string}[]>([
    { name:'Quick LAN Sweep',    cmd:'nmap -sn 192.168.1.0/24',                      tgt:'192.168.1.0/24',   notes:'ARP + ICMP only, no port scan' },
    { name:'Full Port + Version',cmd:'nmap -sV -p- -T4',                              tgt:'192.168.1.0/24',   notes:'All 65535 ports with service detection' },
    { name:'Vuln Scan',          cmd:'nmap -sV --script vuln -T4',                    tgt:'192.168.1.0/24',   notes:'CVE detection via NSE scripts' },
    { name:'SMB Audit',          cmd:'nmap -p 445 --script smb-vuln* -T4',            tgt:'192.168.1.0/24',   notes:'SMB vulnerability check (EternalBlue etc)' },
    { name:'RDP Brute',          cmd:'nmap -p 3389 --script rdp-brute -T4',           tgt:'192.168.1.1',      notes:'RDP credential brute-force' },
    { name:'HTTP Headers',       cmd:'nmap -p 80,443,8080 --script http-headers -T3', tgt:'192.168.1.0/24',   notes:'HTTP server header fingerprint' },
    { name:'SSH Audit',          cmd:'nmap -p 22 --script ssh-auth-methods,ssh2-enum-algos', tgt:'192.168.1.0/24', notes:'SSH cipher and auth audit' },
  ]);
  const [autoLoop, setAutoLoop] = useState(false);
  const [log,      setLog]      = useState<ScanLine[]>([
    { tag:'SYS', cls:'sys', time:now(), msg:'Scanner ready. Configure and press Launch.' },
  ]);
  const [progress, setProgress] = useState(0);
  const [stats, setStats]       = useState({ hosts:0, ports:0, vulns:0 });
  const [customPorts, setCustom] = useState('');
  const bottomRef               = useRef<HTMLDivElement>(null);
  const cmdRef                  = useRef<HTMLInputElement>(null);
  const [cmd, setCmd]           = useState('');

  useEffect(() => { bottomRef.current?.scrollIntoView({ behavior: 'smooth' }); }, [log]);
  useEffect(() => { if (nodeIp) setTarget(nodeIp); }, [nodeIp]);

  const toggleType = (key: string) => {
    setTypes(p => p.includes(key) ? p.filter(k => k !== key) : [...p, key]);
  };

  const launchScan = () => {
    if (running) { setRunning(false); setProgress(0); return; }
    setRunning(true);
    setLog([]);
    setProgress(0);

    const lines = generateScanLog(target, selectedTypes, scope, aggr, nodeIp || undefined);
    let i = 0;
    const interval = setInterval(() => {
      if (i < lines.length) {
        setLog(p => [...p, lines[i]]);
        setProgress(Math.round((i / lines.length) * 100));
        i++;
      } else {
        clearInterval(interval);
        setRunning(false);
        setProgress(100);
        setStats({ hosts: 0, ports: 14, vulns: 3 });
      }
    }, 120);
  };

  const execCmd = (c: string) => {
    const trimmed = c.trim();
    if (!trimmed) return;
    setLog(p => [...p,
      { tag:'CMD', cls:'cmd', time:now(), msg:`> ${trimmed}` },
      { tag:'SYS', cls:'sys', time:now(), msg:`[stub] Command queued: ${trimmed}` },
    ]);
    setCmd('');
  };

  const COL: Record<string, string> = {
    sys: '#444', ok: '#33a84a', warn: '#d48b55', err: '#e05c6e', find: '#5bb8d4', cmd: '#cccccc',
  };

  const runCustomScan = () => {
    setRunning(true);
    setLog([]);
    const t = now();
    const lines: ScanLine[] = [
      { tag:'SYS', cls:'sys', time:t, msg:`[CUSTOM] Running: ${customCmd} ${customTgt}` },
      { tag:'SYS', cls:'sys', time:t, msg:'Executing nmap-compatible command...' },
      { tag:'OK',  cls:'ok',  time:t, msg:`[+] ${customTgt} — scan started` },
      { tag:'SYS', cls:'sys', time:t, msg:'Results will be streamed below' },
      { tag:'FIND',cls:'find',time:t, msg:'192.168.1.1  port 22/tcp   open  ssh    SSH-2.0-OpenSSH_8.9' },
      { tag:'FIND',cls:'find',time:t, msg:'192.168.1.42 port 3306/tcp open  mysql  5.5.5-10.6.12-MariaDB' },
      { tag:'WARN',cls:'warn',time:t, msg:'192.168.1.99 port 445/tcp  open  smb    Samba 4.17 [RISK]' },
      { tag:'ERR', cls:'err', time:t, msg:'192.168.1.99 [VULN] CVE-2017-0144 EternalBlue potentially vulnerable' },
      { tag:'OK',  cls:'ok',  time:t, msg:`Custom scan complete — wire to POST /api/scanner/custom` },
    ];
    let i = 0;
    const iv = setInterval(() => {
      if (i < lines.length) { setLog(p => [...p, lines[i]]); i++; }
      else { clearInterval(iv); setRunning(false); }
    }, 200);
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%', overflow: 'hidden' }}>
      {/* MODE TABS */}
      <div style={{ display:'flex', background:'var(--inset2)', borderBottom:'1px solid #111', flexShrink:0 }}>
        {[{k:'standard',l:'Standard Scanner'},{k:'custom',l:'Custom / Nmap'}].map(m=>(
          <button key={m.k} onClick={()=>setScanMode(m.k as any)} style={{
            padding:'6px 18px', background:scanMode===m.k?'#0d0d0d':'transparent',
            border:'none', borderTop: scanMode===m.k?'2px solid #e05c6e':'2px solid transparent',
            color:scanMode===m.k?'#e8e8e8':'#555', fontFamily:'Courier New', fontSize:11,
            cursor:'pointer', textTransform:'uppercase', letterSpacing:0.8,
          }}>{m.l}</button>
        ))}
      </div>

      {scanMode==='custom' ? (
        /* ── CUSTOM SCANNER ── */
        <div style={{ flex:1, display:'flex', overflow:'hidden' }}>
          {/* Left: builder */}
          <div style={{ width:340, background:'var(--bg)', borderRight:'1px solid #111', display:'flex', flexDirection:'column', overflow:'hidden', flexShrink:0 }}>
            <div style={{ padding:'5px 12px', background:'var(--inset)', borderBottom:'1px solid #0d0d0d', fontSize:10, color:'#777', textTransform:'uppercase', letterSpacing:1 }}>Command Builder</div>
            <div style={{ flex:1, overflowY:'auto', padding:'14px' }}>

              <div style={{ marginBottom:14 }}>
                <div style={{ fontSize:9, color:'var(--tx1)', textTransform:'uppercase', letterSpacing:'1px', marginBottom:6, fontFamily:'Courier New' }}>Target</div>
                <input className="zk-input" value={customTgt} onChange={e=>setCustomTgt(e.target.value)} placeholder="192.168.1.0/24 or single IP"/>
              </div>

              <div style={{ marginBottom:14 }}>
                <div style={{ fontSize:9, color:'var(--tx1)', textTransform:'uppercase', letterSpacing:'1px', marginBottom:6, fontFamily:'Courier New' }}>Nmap Command (editable)</div>
                <textarea value={customCmd} onChange={e=>setCustomCmd(e.target.value)}
                  style={{ width:'100%', background:'var(--bg)', border:'1px solid #1a1a1a', color:'#e8e8e8', fontFamily:'Courier New', fontSize:12, padding:'8px', outline:'none', resize:'vertical', minHeight:80, boxSizing:'border-box' as const }}/>
              </div>

              <div style={{ marginBottom:14 }}>
                <div style={{ fontSize:9, color:'var(--tx1)', textTransform:'uppercase', letterSpacing:'1px', marginBottom:6, fontFamily:'Courier New' }}>Notes</div>
                <input className="zk-input" value={customNotes} onChange={e=>setCustomNotes(e.target.value)} placeholder="Scan purpose / notes..."/>
              </div>

              {/* Quick flags */}
              <div style={{ marginBottom:14 }}>
                <div style={{ fontSize:9, color:'var(--tx1)', textTransform:'uppercase', letterSpacing:'1px', marginBottom:8, fontFamily:'Courier New' }}>Quick Flags</div>
                <div style={{ display:'flex', flexWrap:'wrap', gap:5 }}>
                  {[
                    ['-sS','SYN Scan'],   ['-sV','Svc Ver'],  ['-sC','Scripts'],
                    ['-O','OS Detect'],   ['-A','Aggressive'], ['-T4','Fast'],
                    ['-T1','Stealthy'],  ['-p-','All Ports'],  ['--open','Open Only'],
                    ['--script vuln','Vuln NSE'], ['--script smb-vuln*','SMB Vulns'], ['-Pn','No Ping'],
                  ].map(([flag, name]) => (
                    <button key={flag} onClick={() => setCustomCmd(p => p.includes(flag as string) ? p.replace(' '+flag,'').replace(flag+' ','') : p+' '+flag)}
                      style={{
                        background: customCmd.includes(flag as string)?'#1a0000':'#0d0d0d',
                        border:'1px solid '+(customCmd.includes(flag as string)?'#e05c6e':'#1a1a1a'),
                        color: customCmd.includes(flag as string)?'#e05c6e':'#555',
                        fontFamily:'Courier New', fontSize:9, padding:'3px 8px', cursor:'pointer',
                      }}>
                      {name}
                    </button>
                  ))}
                </div>
              </div>

              {/* Preview */}
              <div style={{ marginBottom:14 }}>
                <div style={{ fontSize:9, color:'var(--tx1)', textTransform:'uppercase', letterSpacing:'1px', marginBottom:6, fontFamily:'Courier New' }}>Full Command Preview</div>
                <div style={{ background:'var(--bg)', border:'1px solid #0d0d0d', padding:'8px 10px', fontFamily:'Courier New', fontSize:11, color:'#e05c6e', wordBreak:'break-all' }}>
                  $ {customCmd} {customTgt}
                </div>
              </div>

              {/* Save / Load */}
              <div style={{ marginBottom:14 }}>
                <div style={{ display:'flex', gap:6, marginBottom:8 }}>
                  <button onClick={() => { if(customNotes||customCmd) setSavedScans(p=>[...p,{name:customNotes||`scan-${Date.now()}`,cmd:customCmd,tgt:customTgt,notes:customNotes}]); }}
                    style={{ flex:1, background:'var(--bg)', border:'1px solid #1a1a1a', color:'#777', fontFamily:'Courier New', fontSize:10, padding:'5px', cursor:'pointer' }}>
                    + Save Preset
                  </button>
                  <button onClick={() => { setCustomCmd('nmap -sV -sC -T4'); setCustomTgt('192.168.1.0/24'); }}
                    style={{ background:'transparent', border:'1px solid #0d0d0d', color:'var(--tx2)', fontFamily:'Courier New', fontSize:10, padding:'5px 10px', cursor:'pointer' }}>
                    Reset
                  </button>
                </div>
              </div>
            </div>

            <div style={{ padding:'10px 12px', borderTop:'1px solid #111', flexShrink:0 }}>
              <button onClick={runCustomScan} disabled={running} style={{
                width:'100%', padding:'10px', fontSize:12, fontWeight:700, letterSpacing:1,
                fontFamily:'Courier New', cursor:running?'default':'pointer',
                background:running?'#0d0d0d':'#1a0000',
                border:`1px solid ${running?'#222':'#e05c6e'}`,
                color:running?'#333':'#e05c6e',
              }}>{running?'[ RUNNING... ]':'[ EXECUTE SCAN ]'}</button>
            </div>
          </div>

          {/* Center: saved presets */}
          <div style={{ width:280, background:'var(--bg)', borderRight:'1px solid #111', display:'flex', flexDirection:'column', overflow:'hidden', flexShrink:0 }}>
            <div style={{ padding:'5px 12px', background:'var(--inset)', borderBottom:'1px solid #0d0d0d', fontSize:10, color:'#777', textTransform:'uppercase', letterSpacing:1 }}>Saved Presets</div>
            <div style={{ flex:1, overflowY:'auto' }}>
              {savedScans.map((sc,i) => (
                <div key={i} style={{ padding:'10px 12px', borderBottom:'1px solid #0d0d0d', cursor:'pointer' }}
                  onMouseEnter={e=>(e.currentTarget.style.background='#0d0d0d')}
                  onMouseLeave={e=>(e.currentTarget.style.background='transparent')}>
                  <div style={{ display:'flex', alignItems:'center', gap:8, marginBottom:4 }}>
                    <span style={{ fontSize:11, color:'#aaaaaa', fontFamily:'Courier New', flex:1, fontWeight:700 }}>{sc.name}</span>
                    <button onClick={()=>{setCustomCmd(sc.cmd);setCustomTgt(sc.tgt);setCustomNotes(sc.notes);}}
                      style={{ fontSize:8, background:'#1a0000', border:'1px solid #e05c6e', color:'#e05c6e', fontFamily:'Courier New', padding:'1px 7px', cursor:'pointer' }}>Load</button>
                  </div>
                  <div style={{ fontSize:10, color:'#e05c6e', fontFamily:'Courier New', marginBottom:3, opacity:0.7 }}>{sc.cmd.slice(0,40)}{sc.cmd.length>40?'...':''}</div>
                  <div style={{ fontSize:9, color:'var(--tx1)', fontFamily:'Courier New' }}>{sc.notes}</div>
                </div>
              ))}
            </div>
          </div>

          {/* Right: output */}
          <div style={{ flex:1, display:'flex', flexDirection:'column', background:'var(--bg)', overflow:'hidden' }}>
            <div style={{ padding:'5px 12px', background:'var(--inset)', borderBottom:'1px solid #0d0d0d', fontSize:10, color:'#777', textTransform:'uppercase', letterSpacing:1, display:'flex', alignItems:'center', gap:10 }}>
              <span>Output</span>
              {running&&<span style={{ color:'#e05c6e' }}>● RUNNING</span>}
              <button onClick={()=>setLog([])} style={{ marginLeft:'auto', background:'transparent', border:'1px solid #111', color:'var(--tx2)', fontFamily:'Courier New', fontSize:9, padding:'2px 8px', cursor:'pointer' }}>Clear</button>
            </div>
            <div style={{ flex:1, overflowY:'auto', padding:'10px 14px', fontFamily:'Courier New', fontSize:12 }}>
              {log.length===0&&<div style={{ color:'var(--tx3)' }}>[*] Configure command and execute</div>}
              {log.map((l,i)=>(
                <div key={i} style={{ display:'flex', gap:10, lineHeight:1.65, marginBottom:1 }}>
                  <span style={{ color:'var(--tx3)', fontSize:10, minWidth:58, flexShrink:0 }}>{l.time}</span>
                  <span style={{ color:l.cls==='ok'?'#33a84a':l.cls==='err'?'#e05c6e':l.cls==='warn'?'#d48b55':l.cls==='find'?'#5bb8d4':'#444' }}>{l.msg}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      ) : (
      <div style={{ display: 'flex', flex: 1, overflow: 'hidden' }}>

      {/* ── CONFIG PANEL ── */}
      <div style={{ width: 270, minWidth: 270, background: 'var(--inset2)', borderRight: '1px solid var(--b1)', display: 'flex', flexDirection: 'column', overflow: 'hidden', flexShrink: 0 }}>
        {targetNode && (
          <div style={{ padding: '7px 12px', background: '#1a0000', borderBottom: '1px solid #e05c6e44', display: 'flex', alignItems: 'center', gap: 8 }}>
            <span style={{ fontSize: 10, color: '#e05c6e', fontFamily: 'Courier New', flex: 1 }}>Single-node scan: {nodeIp}</span>
            {onClose && <button onClick={onClose} style={{ background: 'transparent', border: '1px solid #3d1520', color: '#e05c6e', fontFamily: 'Courier New', fontSize: 9, padding: '2px 7px', cursor: 'pointer' }}>✕</button>}
          </div>
        )}

        <div style={{ flex: 1, overflowY: 'auto' }}>

          {/* TARGET */}
          <div style={{ padding: '10px 14px', borderBottom: '1px solid var(--b1)' }}>
            <span style={{ fontSize: 9, color: 'var(--tx2)', textTransform: 'uppercase', letterSpacing: '1.2px', display: 'block', borderBottom: '1px solid #111', marginBottom: 8, paddingBottom: 4 }}>Target</span>
            <input className="zk-input" value={target} onChange={e => setTarget(e.target.value)} disabled={!!targetNode}
              style={{ opacity: targetNode ? 0.5 : 1 }} />
            <div style={{ marginTop: 10 }}>
              <span style={{ fontSize: 9, color: 'var(--tx2)', textTransform: 'uppercase', letterSpacing: '1.2px', display: 'block', marginBottom: 5 }}>Session</span>
              <select className="zk-select"><option>Corp-Local (eth0)</option><option>Corp-WiFi (wlan0)</option></select>
            </div>
          </div>

          {/* SCAN TYPES */}
          <div style={{ padding: '10px 14px', borderBottom: '1px solid var(--b1)' }}>
            <span style={{ fontSize: 9, color: 'var(--tx2)', textTransform: 'uppercase', letterSpacing: '1.2px', display: 'block', borderBottom: '1px solid #111', marginBottom: 8, paddingBottom: 4 }}>Scan Types</span>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
              {SCAN_TYPES.map(st => (
                <button key={st.key} onClick={() => toggleType(st.key)}
                  style={{
                    display: 'flex', alignItems: 'center', gap: 8, padding: '4px 8px',
                    background: selectedTypes.includes(st.key) ? '#1a0000' : 'transparent',
                    border: `1px solid ${selectedTypes.includes(st.key) ? '#e05c6e' : 'transparent'}`,
                    color: selectedTypes.includes(st.key) ? '#e05c6e' : 'var(--tx1)',
                    fontFamily: 'Courier New', fontSize: 10, cursor: 'pointer', textAlign: 'left',
                  }}>
                  <span style={{ minWidth: 60 }}>{st.label}</span>
                  <span style={{ fontSize: 9, color: selectedTypes.includes(st.key) ? '#e05c6e88' : 'var(--tx2)' }}>{st.desc}</span>
                </button>
              ))}
            </div>
          </div>

          {/* PORT SCOPE */}
          <div style={{ padding: '10px 14px', borderBottom: '1px solid var(--b1)' }}>
            <span style={{ fontSize: 9, color: 'var(--tx2)', textTransform: 'uppercase', letterSpacing: '1.2px', display: 'block', borderBottom: '1px solid #111', marginBottom: 8, paddingBottom: 4 }}>Port Scope</span>
            {PORT_SCOPES.map(ps => (
              <div key={ps.key} onClick={() => setScope(ps.key)}
                style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '4px 8px', marginBottom: 3, cursor: 'pointer', background: scope === ps.key ? '#1a0000' : 'transparent', border: `1px solid ${scope === ps.key ? '#e05c6e' : 'transparent'}` }}>
                <span style={{ fontSize: 10, color: scope === ps.key ? '#e05c6e' : 'var(--tx1)', fontFamily: 'Courier New', minWidth: 70 }}>{ps.label}</span>
                <span style={{ fontSize: 9, color: scope === ps.key ? '#e05c6e88' : 'var(--tx2)', fontFamily: 'Courier New' }}>{ps.range}</span>
              </div>
            ))}
            {scope === 'custom' && (
              <input className="zk-input" style={{ marginTop: 6 }} placeholder="22,80,443,3389..." value={customPorts} onChange={e => setCustom(e.target.value)} />
            )}
          </div>

          {/* AGGRESSION */}
          <div style={{ padding: '10px 14px', borderBottom: '1px solid var(--b1)' }}>
            <span style={{ fontSize: 9, color: 'var(--tx2)', textTransform: 'uppercase', letterSpacing: '1.2px', display: 'block', borderBottom: '1px solid #111', marginBottom: 8, paddingBottom: 4 }}>Aggression</span>
            <div style={{ display: 'flex', gap: 4 }}>
              {['STEALTH','STD','AGGR'].map(a => (
                <button key={a} onClick={() => setAggr(a)} className={`zk-btn${aggr === a ? ' active' : ''}`} style={{ flex: 1, fontSize: 10 }}>{a}</button>
              ))}
            </div>
            <div style={{ fontSize: 9, color: 'var(--tx2)', marginTop: 6, fontFamily: 'Courier New' }}>
              { aggr==='STEALTH'?'SYN-only · low noise · slow':aggr==='STD'?'Standard connect · moderate':'Aggressive · fast · noisy'}
            </div>
          </div>

          {/* AUTO LOOP */}
          <div style={{ padding: '10px 14px' }}>
            <span style={{ fontSize: 9, color: 'var(--tx2)', textTransform: 'uppercase', letterSpacing: '1.2px', display: 'block', borderBottom: '1px solid #111', marginBottom: 8, paddingBottom: 4 }}>Auto Loop</span>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 8 }}>
              <div style={{ fontSize: 9, color: 'var(--tx2)', fontFamily: 'Courier New' }}>Repeat scan continuously</div>
              <button className={`zk-btn${autoLoop ? ' active' : ''}`} style={{ minWidth: 44 }} onClick={() => setAutoLoop(p => !p)}>{autoLoop ? 'ON' : 'OFF'}</button>
            </div>
            {autoLoop && (
              <div style={{ display: 'flex', gap: 4 }}>
                {['30s','1m','5m','15m'].map(iv => (
                  <button key={iv} className="zk-btn" style={{ flex: 1, fontSize: 9 }}>{iv}</button>
                ))}
              </div>
            )}
          </div>
        </div>

        {/* LAUNCH */}
        <div style={{ padding: '10px 12px', borderTop: '1px solid var(--b1)', flexShrink: 0 }}>
          <button onClick={launchScan} style={{
            width: '100%', padding: '10px', fontSize: 12, fontWeight: 700, letterSpacing: 1,
            fontFamily: 'Courier New', cursor: 'pointer', textTransform: 'uppercase',
            background: running ? 'var(--inset2)' : '#1a0000',
            border: `1px solid ${running ? 'var(--b2)' : '#e05c6e'}`,
            color: running ? 'var(--tx2)' : '#e05c6e',
          }}>
            {running ? '[ STOP SCAN ]' : `[ LAUNCH SCAN${targetNode ? ' (NODE)' : ''} ]`}
          </button>
        </div>
      </div>

      {/* ── OUTPUT ── */}
      <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>

        {/* Top bar */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '0 12px', height: 34, background: 'var(--inset)', borderBottom: '1px solid #1a1a1a', flexShrink: 0 }}>
          <span style={{ fontSize: 10, color: 'var(--tx2)', textTransform: 'uppercase', letterSpacing: 1, fontFamily: 'Courier New' }}>Scan Output</span>
          <div style={{ width: 5, height: 5, borderRadius: '50%', background: running ? '#e05c6e' : '#222' }} />
          <span style={{ fontSize: 11, color: running ? '#e05c6e' : '#333', fontFamily: 'Courier New' }}>{running ? '[RUNNING]' : progress === 100 ? '[DONE]' : 'Idle'}</span>
          {progress > 0 && <span style={{ fontSize: 10, color: 'var(--tx2)', fontFamily: 'Courier New', marginLeft: 4 }}>{progress}%</span>}
          <div style={{ marginLeft: 'auto', display: 'flex', gap: 6 }}>
            <button className="zk-btn" style={{ fontSize: 10, padding: '2px 10px' }} onClick={() => setLog([])}>Clear</button>
            <button className="zk-btn" style={{ fontSize: 10, padding: '2px 10px' }}>Export</button>
            <button className="zk-btn" style={{ fontSize: 10, padding: '2px 10px' }}>Save Results</button>
          </div>
        </div>

        {/* Progress */}
        <div style={{ height: 2, background: 'var(--inset)', flexShrink: 0 }}>
          <div style={{ height: 2, background: '#e05c6e', width: `${progress}%`, transition: 'width 0.2s' }} />
        </div>

        <div style={{ flex: 1, display: 'flex', overflow: 'hidden' }}>

          {/* TERMINAL */}
          <div style={{ flex: 1, background: 'var(--bg)', padding: '10px 14px', overflowY: 'auto', fontFamily: 'Courier New', fontSize: 12 }}
            onClick={() => cmdRef.current?.focus()}>
            {log.map((line, i) => (
              <div key={i} style={{ display: 'flex', gap: 10, alignItems: 'baseline', padding: '2px 0', borderBottom: '1px solid rgba(30,30,30,0.5)' }}>
                <span style={{ fontSize: 10, color: 'var(--tx3)', minWidth: 58, flexShrink: 0 }}>{line.time}</span>
                <span style={{ color: COL[line.cls] || '#888', fontWeight: line.tag === 'CMD' ? 700 : 400, minWidth: 36, flexShrink: 0, fontSize: 10 }}>{line.tag}</span>
                <span style={{ color: COL[line.cls] || '#888' }}>{line.msg}</span>
              </div>
            ))}
            {running && (
              <div style={{ display: 'flex', gap: 10, padding: '3px 0' }}>
                <span style={{ fontSize: 10, color: 'var(--tx3)', minWidth: 58 }}>--:--:--</span>
                <span style={{ color: '#e05c6e' }}>Scanning<span className="cursor" /></span>
              </div>
            )}
            <div ref={bottomRef} />
          </div>

          {/* DISCOVERED NODES */}
          <div style={{ width: 240, background: 'var(--panel)', borderLeft: '1px solid var(--b1)', display: 'flex', flexDirection: 'column', overflow: 'hidden', flexShrink: 0 }}>
            <div className="sec-hdr">
              <span>Discovered Nodes</span>
              <span style={{ color: '#e05c6e' }}>{0}</span>
            </div>
            <div style={{ flex: 1, overflowY: 'auto', background: 'var(--bg)' }}>
              {([] as import('@/lib/models/localNetwork/networkModel').NetworkNode[]).map(node => {
                const hasRisk = node.ports.some(() => false);
                const col = hasRisk ? '#e05c6e' : '#33a84a';
                return (
                  <div key={node.ipv4} className="node-card"
                    style={{ padding: '8px 10px', borderBottom: '1px solid var(--b1)' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 3 }}>
                      <span style={{ fontSize: 10, color: col, flexShrink: 0 }}>{hasRisk ? '[!]' : '[*]'}</span>
                      <span style={{ fontSize: 11, fontWeight: 700, color: '#5bb8d4', flex: 1 }}>{node.ipv4}</span>
                      {node.isAgent && <span style={{ fontSize: 8, padding: '0 4px', background: '#1a0000', border: '1px solid #e05c6e', color: '#e05c6e' }}>ZK</span>}
                    </div>
                    <div style={{ fontSize: 10, color: 'var(--tx2)', marginBottom: 4, fontFamily: 'Courier New' }}>{node.mac} · {node.os}</div>
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: 2 }}>
                      {node.ports.map(p => (
                        <span key={p.number} className={`port-tag${false ? ' risk' : ' open'}`}>{p.number}</span>
                      ))}
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        </div>

        {/* PROMPT + STATS */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '5px 12px', borderTop: '1px solid var(--b1)', background: 'var(--panel)', flexShrink: 0 }}>
          <span style={{ fontSize: 12, color: '#e05c6e', whiteSpace: 'nowrap', fontFamily: 'Courier New', fontWeight: 700 }}>[ZK-ROOT] $&gt;</span>
          <input ref={cmdRef} value={cmd} onChange={e => setCmd(e.target.value)}
            onKeyDown={e => { if (e.key === 'Enter') { execCmd(cmd); } }}
            style={{ flex: 1, background: 'transparent', border: 'none', color: '#cccccc', fontFamily: 'Courier New', fontSize: 12, outline: 'none' }}
            placeholder="command..." />
        </div>
        <div style={{ display: 'flex', gap: 24, alignItems: 'center', padding: '3px 12px', background: 'var(--inset)', borderTop: '1px solid #0d0d0d', flexShrink: 0, fontSize: 11, fontFamily: 'Courier New' }}>
          <span><span style={{ fontWeight: 700, color: '#cccccc', fontSize: 13 }}>{stats.hosts || 0}</span><span style={{ color: 'var(--tx2)', marginLeft: 4 }}>hosts</span></span>
          <span><span style={{ fontWeight: 700, color: '#cccccc', fontSize: 13 }}>{stats.ports || 14}</span><span style={{ color: 'var(--tx2)', marginLeft: 4 }}>ports</span></span>
          <span><span style={{ fontWeight: 700, color: '#e05c6e', fontSize: 13 }}>{stats.vulns || 3}</span><span style={{ color: 'var(--tx2)', marginLeft: 4 }}>vulns</span></span>
          <span style={{ marginLeft: 'auto', color: 'var(--tx3)' }}>
            {aggr} · {selectedTypes.join('+') || 'none'} · {scope}
          </span>
        </div>
      </div>
    </div>
      )}
    </div>
  );
}
