import { useState } from 'react';

type ScanStatus = 'idle'|'scanning'|'done';
type PortState  = 'open'|'closed'|'filtered';

interface ScanPort  { port:number; state:PortState; service:string; version:string; }
interface ScanHost  { ip:string; hostname:string; os:string; ttl:number; ports:ScanPort[]; vulns:string[]; mac?:string; }
interface ScanResult{ session:string; subnet:string; hostsUp:number; hostsTotal:number; hosts:ScanHost[]; elapsed:string; }

const DEMO: ScanResult = {
  session:'NS-20260608-031244', subnet:'192.168.5.0/24', hostsUp:7, hostsTotal:254, elapsed:'38.2s',
  hosts:[
    { ip:'192.168.5.1',   hostname:'gateway.local',    os:'Linux 5.x (router)',   ttl:64,
      ports:[
        {port:22,  state:'open',  service:'ssh',    version:'OpenSSH 9.3'},
        {port:80,  state:'open',  service:'http',   version:'nginx/1.25'},
        {port:443, state:'open',  service:'https',  version:'nginx/1.25'},
      ], vulns:[], mac:'AA:BB:CC:11:22:33' },
    { ip:'192.168.5.10',  hostname:'WIN-DC01.corp',     os:'Windows Server 2019', ttl:128,
      ports:[
        {port:53,   state:'open',  service:'dns',    version:'MS DNS'},
        {port:88,   state:'open',  service:'kerberos',version:''},
        {port:135,  state:'open',  service:'msrpc',  version:'MS RPC'},
        {port:139,  state:'open',  service:'netbios',version:''},
        {port:389,  state:'open',  service:'ldap',   version:'MS AD'},
        {port:445,  state:'open',  service:'smb',    version:'SMBv3.1.1'},
        {port:636,  state:'open',  service:'ldaps',  version:'MS AD'},
        {port:3389, state:'open',  service:'rdp',    version:'MS RDP'},
      ], vulns:['MS17-010 (EternalBlue)','CVE-2020-1472 (Zerologon)'], mac:'DE:AD:BE:EF:10:01' },
    { ip:'192.168.5.20',  hostname:'UBUNTU-WEB',        os:'Ubuntu 22.04 LTS',    ttl:64,
      ports:[
        {port:22,  state:'open',  service:'ssh',    version:'OpenSSH 8.9'},
        {port:80,  state:'open',  service:'http',   version:'Apache 2.4.55'},
        {port:3306,state:'open',  service:'mysql',  version:'MySQL 8.0'},
      ], vulns:['CVE-2023-1234 (Apache mod_auth)'], mac:'DE:AD:BE:EF:20:01' },
    { ip:'192.168.5.30',  hostname:'WIN-WS03',           os:'Windows 10 22H2',     ttl:128,
      ports:[
        {port:135,  state:'open', service:'msrpc',  version:''},
        {port:445,  state:'open', service:'smb',    version:'SMBv3.1.1'},
        {port:3389, state:'open', service:'rdp',    version:''},
      ], vulns:[], mac:'DE:AD:BE:EF:30:01' },
    { ip:'192.168.5.50',  hostname:'WIN-EXCH01',         os:'Windows Server 2019', ttl:128,
      ports:[
        {port:25,   state:'open', service:'smtp',   version:'MS Exchange'},
        {port:80,   state:'open', service:'http',   version:'MS OWA'},
        {port:443,  state:'open', service:'https',  version:'MS OWA'},
        {port:445,  state:'open', service:'smb',    version:'SMBv3.1.1'},
      ], vulns:['CVE-2021-26855 (ProxyLogon)'], mac:'DE:AD:BE:EF:50:01' },
  ],
};

const PORT_COL: Record<PortState,string> = { open:'#33a84a', closed:'#2a2a2a', filtered:'#c8a84b' };

export default function NetworkScannerView() {
  const [subnet,     setSubnet]    = useState('192.168.5.0/24');
  const [ports,      setPorts]     = useState('22,80,135,139,389,443,445,636,3389,3306,25,53,88');
  const [threads,    setThreads]   = useState('64');
  const [status,     setStatus]    = useState<ScanStatus>('idle');
  const [result,     setResult]    = useState<ScanResult|null>(null);
  const [selected,   setSelected]  = useState<ScanHost|null>(null);
  const [progress,   setProgress]  = useState(0);
  const [logLines,   setLogLines]  = useState<string[]>([]);

  const scan = () => {
    setStatus('scanning'); setProgress(0); setLogLines([]); setResult(null); setSelected(null);

    const lines = [
      `[*] Starting scan of ${subnet}`,
      `[*] ICMP sweep — discovering live hosts...`,
      '[+] Host up: 192.168.5.1 (ttl=64)',
      '[+] Host up: 192.168.5.10 (ttl=128)',
      '[+] Host up: 192.168.5.20 (ttl=64)',
      '[+] Host up: 192.168.5.30 (ttl=128)',
      '[+] Host up: 192.168.5.50 (ttl=128)',
      `[*] TCP port scan on ${ports}`,
      '[+] 192.168.5.10:445 open (smb)',
      '[+] 192.168.5.10:88  open (kerberos)',
      '[+] 192.168.5.20:80  open (http/Apache)',
      '[+] 192.168.5.50:443 open (https/OWA)',
      '[!] Vuln match: 192.168.5.10 → MS17-010',
      '[!] Vuln match: 192.168.5.50 → CVE-2021-26855',
      '[*] Fingerprinting OS and services...',
      '[+] Scan complete — results sent to /api/recon',
    ];
    lines.forEach((line,i)=>{
      setTimeout(()=>{
        setLogLines(p=>[...p,line]);
        setProgress(Math.round(((i+1)/lines.length)*100));
        if (i===lines.length-1) { setStatus('done'); setResult(DEMO); }
      }, (i+1)*250 + Math.random()*100);
    });
  };

  const vulnHosts = result?.hosts.filter(h=>h.vulns.length>0) ?? [];

  return (
    <div style={{ display:'flex', flexDirection:'column', height:'100%', overflow:'hidden', fontFamily:'Courier New' }}>

      {/* Scan config bar */}
      <div style={{ padding:'8px 14px', background:'#0d0d0d', borderBottom:'1px solid #1a1a1a', display:'flex', gap:10, alignItems:'flex-end', flexShrink:0 }}>
        <div>
          <div style={{ fontSize:9, color:'#333', textTransform:'uppercase', letterSpacing:1, marginBottom:3 }}>Subnet (CIDR)</div>
          <input value={subnet} onChange={e=>setSubnet(e.target.value)} disabled={status==='scanning'} style={{ width:160, background:'#040404', border:'1px solid #1e1e1e', color:'#ccc', fontFamily:'Courier New', fontSize:11, padding:'4px 8px', outline:'none' }}/>
        </div>
        <div style={{ flex:1 }}>
          <div style={{ fontSize:9, color:'#333', textTransform:'uppercase', letterSpacing:1, marginBottom:3 }}>Ports</div>
          <input value={ports} onChange={e=>setPorts(e.target.value)} disabled={status==='scanning'} style={{ width:'100%', background:'#040404', border:'1px solid #1e1e1e', color:'#ccc', fontFamily:'Courier New', fontSize:11, padding:'4px 8px', outline:'none' }}/>
        </div>
        <div>
          <div style={{ fontSize:9, color:'#333', textTransform:'uppercase', letterSpacing:1, marginBottom:3 }}>Threads</div>
          <input value={threads} onChange={e=>setThreads(e.target.value)} style={{ width:60, background:'#040404', border:'1px solid #1e1e1e', color:'#ccc', fontFamily:'Courier New', fontSize:11, padding:'4px 8px', outline:'none' }}/>
        </div>
        <button onClick={scan} disabled={status==='scanning'} style={{
          background: status==='scanning'?'#0d0d0d':'#1a0000',
          border:`1px solid ${status==='scanning'?'#222':'#e05c6e'}`,
          color: status==='scanning'?'#333':'#e05c6e',
          fontFamily:'Courier New', fontSize:11, fontWeight:700,
          padding:'4px 20px', cursor:status==='scanning'?'default':'pointer', letterSpacing:1,
        }}>
          {status==='scanning'?'[ SCANNING... ]':'[ SCAN ]'}
        </button>
        {status==='scanning' && (
          <div style={{ width:120, alignSelf:'center' }}>
            <div style={{ height:4, background:'#111', borderRadius:2 }}>
              <div style={{ height:'100%', width:`${progress}%`, background:'#e05c6e', borderRadius:2, transition:'width 0.2s' }}/>
            </div>
            <div style={{ fontSize:9, color:'#555', marginTop:2 }}>{progress}%</div>
          </div>
        )}
        {result && <span style={{ fontSize:10, color:'#33a84a', alignSelf:'center' }}>{result.hostsUp} hosts · {result.elapsed}</span>}
      </div>

      <div style={{ flex:1, display:'flex', overflow:'hidden' }}>

        {/* Log panel */}
        <div style={{ width:300, background:'#050505', borderRight:'1px solid #1a1a1a', display:'flex', flexDirection:'column', flexShrink:0 }}>
          <div style={{ padding:'4px 10px', background:'#0d0d0d', borderBottom:'1px solid #1a1a1a', fontSize:9, color:'#333', textTransform:'uppercase', letterSpacing:1 }}>Scan Output</div>
          <div style={{ flex:1, overflowY:'auto', padding:'6px 10px' }}>
            {logLines.length === 0 && <div style={{ fontSize:10, color:'#1a1a1a' }}>awaiting scan…</div>}
            {logLines.map((l,i)=>(
              <div key={i} style={{ fontSize:10, color:l.startsWith('[+]')?'#33a84a':l.startsWith('[!]')?'#c8a84b':'#444', lineHeight:1.8, fontFamily:'monospace' }}>
                {l}
              </div>
            ))}
          </div>
        </div>

        {/* Host list */}
        <div style={{ flex:1, display:'flex', flexDirection:'column', overflow:'hidden' }}>
          {/* Vuln banner */}
          {vulnHosts.length > 0 && (
            <div style={{ padding:'4px 14px', background:'#1a0000', borderBottom:'1px solid #3d1520', fontSize:10, color:'#e05c6e', flexShrink:0 }}>
              [!] {vulnHosts.length} host(s) with critical vulnerabilities detected
            </div>
          )}

          {/* Host table header */}
          <div style={{ display:'grid', gridTemplateColumns:'110px 140px 160px 50px 1fr 80px', padding:'4px 14px', background:'#111', borderBottom:'1px solid #1a1a1a', fontSize:9, color:'#333', textTransform:'uppercase', letterSpacing:0.8, flexShrink:0 }}>
            <span>IP</span><span>Hostname</span><span>OS</span><span>TTL</span><span>Open Ports</span><span>Vulns</span>
          </div>

          <div style={{ flex:1, overflowY:'auto' }}>
            {!result && status === 'idle' && (
              <div style={{ padding:'20px 14px', color:'#1a1a1a', fontSize:11 }}>[*] Configure subnet and click SCAN — calls LocalFingerPrint via /api/recon</div>
            )}
            {result?.hosts.map(h=>(
              <div key={h.ip}
                onClick={()=>setSelected(selected?.ip===h.ip?null:h)}
                style={{
                  display:'grid', gridTemplateColumns:'110px 140px 160px 50px 1fr 80px',
                  padding:'6px 14px', borderBottom:'1px solid #0d0d0d', cursor:'pointer',
                  background: selected?.ip===h.ip?'#0d0d14':h.vulns.length>0?'#0d0000':'transparent',
                }}>
                <span style={{ fontSize:11, color:'#777', fontFamily:'monospace' }}>{h.ip}</span>
                <span style={{ fontSize:10, color:'#555', overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap' }}>{h.hostname}</span>
                <span style={{ fontSize:10, color:'#444' }}>{h.os}</span>
                <span style={{ fontSize:10, color:'#2a2a2a' }}>{h.ttl}</span>
                <div style={{ display:'flex', gap:4, flexWrap:'wrap' }}>
                  {h.ports.filter(p=>p.state==='open').map(p=>(
                    <span key={p.port} style={{ fontSize:9, color:PORT_COL[p.state], border:`1px solid ${PORT_COL[p.state]}44`, padding:'1px 4px' }}>{p.port}</span>
                  ))}
                </div>
                <span style={{ fontSize:10, color:h.vulns.length>0?'#e05c6e':'#2a2a2a', fontWeight:h.vulns.length>0?700:400 }}>
                  {h.vulns.length>0 ? `[!] ${h.vulns.length}` : '—'}
                </span>
              </div>
            ))}
          </div>
        </div>

        {/* Host detail */}
        {selected && (
          <div style={{ width:240, background:'#0a0a0a', borderLeft:'1px solid #1a1a1a', padding:'10px', overflowY:'auto', flexShrink:0 }}>
            <div style={{ fontSize:11, color:'#cccccc', fontWeight:700, marginBottom:2 }}>{selected.ip}</div>
            <div style={{ fontSize:10, color:'#555', marginBottom:6 }}>{selected.hostname}</div>
            <div style={{ fontSize:9, color:'#333', marginBottom:10 }}>{selected.os}</div>

            {selected.mac && <div style={{ fontSize:9, color:'#2a2a2a', marginBottom:8 }}>MAC: {selected.mac}</div>}

            <div style={{ fontSize:9, color:'#2a2a2a', textTransform:'uppercase', letterSpacing:1, marginBottom:6 }}>Ports</div>
            {selected.ports.map(p=>(
              <div key={p.port} style={{ display:'flex', justifyContent:'space-between', marginBottom:4, fontSize:10 }}>
                <span style={{ color:PORT_COL[p.state], minWidth:36 }}>{p.port}</span>
                <span style={{ color:'#444', flex:1, marginLeft:6 }}>{p.service}</span>
                <span style={{ color:'#2a2a2a', fontSize:9 }}>{p.version.slice(0,18)}</span>
              </div>
            ))}

            {selected.vulns.length > 0 && (
              <>
                <div style={{ fontSize:9, color:'#e05c6e', textTransform:'uppercase', letterSpacing:1, margin:'10px 0 6px' }}>Vulnerabilities</div>
                {selected.vulns.map(v=>(
                  <div key={v} style={{ fontSize:10, color:'#e05c6e', marginBottom:4, lineHeight:1.4 }}>[!] {v}</div>
                ))}
              </>
            )}

            <button style={{ width:'100%', marginTop:12, background:'#1a0000', border:'1px solid #e05c6e', color:'#e05c6e', fontFamily:'Courier New', fontSize:10, padding:'4px', cursor:'pointer' }}>
              SEND TO AGENT
            </button>
          </div>
        )}
      </div>
    </div>
  );
}
