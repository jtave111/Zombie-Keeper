import { useState } from 'react';

interface Process {
  pid: number; ppid: number; name: string; user: string;
  cpu: string; mem: string; path: string; cmdline: string;
  marked: boolean; suspicious: boolean;
}

const MOCK_PROCS: Record<string, Process[]> = {
  'ZK-001 · WIN-DC01': [
    {pid:4,    ppid:0,    name:'System',          user:'NT AUTHORITY\\SYSTEM',cpu:'0.0',mem:'0.1',  path:'',                                     cmdline:'',                              marked:false,suspicious:false},
    {pid:764,  ppid:4,    name:'smss.exe',         user:'NT AUTHORITY\\SYSTEM',cpu:'0.0',mem:'0.2',  path:'C:\\Windows\\System32\\smss.exe',       cmdline:'\\SystemRoot\\System32\\smss.exe',marked:false,suspicious:false},
    {pid:992,  ppid:764,  name:'csrss.exe',         user:'NT AUTHORITY\\SYSTEM',cpu:'0.0',mem:'1.2',  path:'C:\\Windows\\System32\\csrss.exe',      cmdline:'',                              marked:false,suspicious:false},
    {pid:1024, ppid:764,  name:'wininit.exe',       user:'NT AUTHORITY\\SYSTEM',cpu:'0.0',mem:'0.8',  path:'C:\\Windows\\System32\\wininit.exe',    cmdline:'',                              marked:false,suspicious:false},
    {pid:1180, ppid:1024, name:'services.exe',      user:'NT AUTHORITY\\SYSTEM',cpu:'0.0',mem:'4.2',  path:'C:\\Windows\\System32\\services.exe',   cmdline:'',                              marked:false,suspicious:false},
    {pid:1188, ppid:1024, name:'lsass.exe',         user:'NT AUTHORITY\\SYSTEM',cpu:'0.2',mem:'12.4', path:'C:\\Windows\\System32\\lsass.exe',      cmdline:'',                              marked:false,suspicious:false},
    {pid:2440, ppid:1180, name:'svchost.exe',       user:'NT AUTHORITY\\SYSTEM',cpu:'0.1',mem:'6.2',  path:'C:\\Windows\\System32\\svchost.exe',    cmdline:'-k DcomLaunch',                 marked:false,suspicious:false},
    {pid:2588, ppid:1180, name:'svchost.exe',       user:'NT AUTHORITY\\NETWORK SERVICE',cpu:'0.0',mem:'3.8',path:'C:\\Windows\\System32\\svchost.exe',cmdline:'-k netsvcs',              marked:false,suspicious:false},
    {pid:3204, ppid:1180, name:'spoolsv.exe',       user:'NT AUTHORITY\\SYSTEM',cpu:'0.0',mem:'8.1',  path:'C:\\Windows\\System32\\spoolsv.exe',    cmdline:'',                              marked:false,suspicious:false},
    {pid:4412, ppid:3204, name:'svchosts.exe',      user:'NT AUTHORITY\\SYSTEM',cpu:'2.1',mem:'14.8', path:'C:\\Windows\\Temp\\svchosts.exe',       cmdline:'-s c2.corp:4444',               marked:false,suspicious:true},
    {pid:4900, ppid:2440, name:'explorer.exe',      user:'CORP\\Administrator', cpu:'0.4',mem:'22.1', path:'C:\\Windows\\explorer.exe',             cmdline:'',                              marked:false,suspicious:false},
    {pid:5312, ppid:4900, name:'powershell.exe',    user:'CORP\\Administrator', cpu:'8.2',mem:'46.3', path:'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',cmdline:'-ep bypass -enc …',marked:false,suspicious:true},
  ],
  'ZK-002 · UBUNTU-WEB': [
    {pid:1,    ppid:0,    name:'systemd',          user:'root',    cpu:'0.0',mem:'0.8',  path:'/sbin/init',            cmdline:'',                      marked:false,suspicious:false},
    {pid:612,  ppid:1,    name:'sshd',             user:'root',    cpu:'0.0',mem:'2.1',  path:'/usr/sbin/sshd',        cmdline:'/usr/sbin/sshd -D',     marked:false,suspicious:false},
    {pid:882,  ppid:1,    name:'apache2',          user:'www-data',cpu:'1.2',mem:'12.3', path:'/usr/sbin/apache2',     cmdline:'/usr/sbin/apache2 -D FOREGROUND',marked:false,suspicious:false},
    {pid:1244, ppid:1,    name:'mysqld',           user:'mysql',   cpu:'0.8',mem:'48.2', path:'/usr/sbin/mysqld',      cmdline:'--defaults-file=/etc/mysql/my.cnf',marked:false,suspicious:false},
    {pid:3109, ppid:1,    name:'.update',          user:'root',    cpu:'0.0',mem:'1.2',  path:'/tmp/.update',          cmdline:'/tmp/.update -s 192.168.5.81:4444',marked:false,suspicious:true},
    {pid:3410, ppid:3109, name:'bash',             user:'root',    cpu:'0.0',mem:'2.4',  path:'/bin/bash',             cmdline:'bash -i',               marked:false,suspicious:true},
  ],
};

const AGENTS = Object.keys(MOCK_PROCS);

export default function ProcessesView() {
  const [agent,   setAgent]  = useState(AGENTS[0]);
  const [procs,   setProcs]  = useState<Record<string,Process[]>>(MOCK_PROCS);
  const [search,  setSearch] = useState('');
  const [selected,setSelected]=useState<Process|null>(null);
  const [showSusp,setShowSusp]=useState(false);

  const allProcs = procs[agent] ?? [];
  const visible  = allProcs.filter(p => {
    const matchS = !search || p.name.toLowerCase().includes(search.toLowerCase()) || String(p.pid).includes(search);
    const matchF = !showSusp || p.suspicious;
    return matchS && matchF;
  });

  const mark   = (pid:number) => setProcs(p=>({ ...p, [agent]: p[agent].map(pr=>pr.pid===pid?{...pr,marked:!pr.marked}:pr) }));
  const kill   = (pid:number) => setProcs(p=>({ ...p, [agent]: p[agent].filter(pr=>pr.pid!==pid) }));

  const suspCount = allProcs.filter(p=>p.suspicious).length;

  return (
    <div style={{ display:'flex', flexDirection:'column', height:'100%', overflow:'hidden', fontFamily:'Courier New' }}>

      {/* Header */}
      <div style={{ padding:'7px 14px', background:'#0d0d0d', borderBottom:'1px solid #1a1a1a', display:'flex', gap:10, alignItems:'center', flexShrink:0 }}>
        <select value={agent} onChange={e=>{ setAgent(e.target.value); setSelected(null); }}
          style={{ background:'#040404', border:'1px solid #1e1e1e', color:'#ccc', fontFamily:'Courier New', fontSize:11, padding:'4px 8px', outline:'none', appearance:'none' }}>
          {AGENTS.map(a=><option key={a}>{a}</option>)}
        </select>

        <input value={search} onChange={e=>setSearch(e.target.value)} placeholder="filter name/pid…"
          style={{ width:160, background:'#040404', border:'1px solid #1e1e1e', color:'#777', fontFamily:'Courier New', fontSize:11, padding:'4px 8px', outline:'none' }}/>

        <button onClick={()=>setShowSusp(s=>!s)} style={{
          background: showSusp?'#1a0000':'transparent',
          border:`1px solid ${showSusp?'#e05c6e':'#1a1a1a'}`,
          color: showSusp?'#e05c6e':'#333',
          fontFamily:'Courier New', fontSize:10, padding:'3px 10px', cursor:'pointer',
        }}>
          {showSusp?'▼ suspicious':'▽ suspicious'}
          {suspCount>0 && <span style={{ marginLeft:6, background:'#1a0000', color:'#e05c6e', padding:'0 4px', border:'1px solid #3d1520' }}>{suspCount}</span>}
        </button>

        <span style={{ marginLeft:'auto', fontSize:10, color:'#333' }}>{visible.length} procs</span>

        <button style={{ background:'#0d0d0d', border:'1px solid #1a1a1a', color:'#444', fontFamily:'Courier New', fontSize:10, padding:'3px 12px', cursor:'pointer' }}>
          REFRESH
        </button>
      </div>

      {suspCount > 0 && (
        <div style={{ padding:'4px 14px', background:'#1a0000', borderBottom:'1px solid #3d1520', fontSize:10, color:'#e05c6e', flexShrink:0 }}>
          [!] {suspCount} suspicious process(es) detected — review recommended
        </div>
      )}

      <div style={{ flex:1, display:'flex', overflow:'hidden' }}>

        {/* Process table */}
        <div style={{ flex:1, overflowY:'auto' }}>
          <div style={{ display:'grid', gridTemplateColumns:'60px 60px 160px 160px 60px 60px 1fr', padding:'4px 14px', background:'#111', borderBottom:'1px solid #1a1a1a', fontSize:9, color:'#333', textTransform:'uppercase', letterSpacing:0.8, position:'sticky', top:0 }}>
            <span>PID</span><span>PPID</span><span>Name</span><span>User</span><span>CPU%</span><span>MEM</span><span>Cmdline</span>
          </div>
          {visible.map(p=>(
            <div key={p.pid}
              onClick={()=>setSelected(selected?.pid===p.pid?null:p)}
              style={{
                display:'grid', gridTemplateColumns:'60px 60px 160px 160px 60px 60px 1fr',
                padding:'5px 14px', borderBottom:'1px solid #0d0d0d', cursor:'pointer', alignItems:'center',
                background: selected?.pid===p.pid?'#0d0d14': p.suspicious?'#0d0000':'transparent',
              }}>
              <span style={{ fontSize:10, color:p.marked?'#e05c6e':p.suspicious?'#c8a84b':'#555', fontWeight:p.suspicious?700:400 }}>{p.pid}</span>
              <span style={{ fontSize:9, color:'#333' }}>{p.ppid||'—'}</span>
              <span style={{ fontSize:11, color:p.suspicious?'#c8a84b':p.marked?'#e05c6e':'#777', fontWeight:p.suspicious?700:400 }}>
                {p.suspicious && '⚠ '}{p.name}
              </span>
              <span style={{ fontSize:9, color:'#444', overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap' }}>{p.user.replace('NT AUTHORITY\\','').replace('CORP\\','')}</span>
              <span style={{ fontSize:10, color:parseFloat(p.cpu)>5?'#d48b55':'#333' }}>{p.cpu}</span>
              <span style={{ fontSize:10, color:'#333' }}>{p.mem} MB</span>
              <span style={{ fontSize:9, color:'#2a2a2a', overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap' }}>{p.cmdline||p.path}</span>
            </div>
          ))}
        </div>

        {/* Detail + actions */}
        {selected && (
          <div style={{ width:240, background:'#0a0a0a', borderLeft:'1px solid #1a1a1a', padding:'12px', flexShrink:0, overflowY:'auto' }}>
            <div style={{ fontSize:12, color: selected.suspicious?'#c8a84b':'#ccc', fontWeight:700, marginBottom:4 }}>
              {selected.suspicious && '⚠ '}{selected.name}
            </div>
            <div style={{ fontSize:10, color:'#444', marginBottom:10 }}>PID {selected.pid} · PPID {selected.ppid}</div>

            {([
              ['User',    selected.user.split('\\').pop()!],
              ['CPU',     selected.cpu + '%'],
              ['Memory',  selected.mem + ' MB'],
            ] as [string,string][]).map(([k,v])=>(
              <div key={k} style={{ display:'flex', justifyContent:'space-between', marginBottom:5, fontSize:10 }}>
                <span style={{ color:'#2a2a2a' }}>{k}</span>
                <span style={{ color:'#555' }}>{v}</span>
              </div>
            ))}

            {selected.path && (
              <div style={{ marginTop:6, marginBottom:8 }}>
                <div style={{ fontSize:9, color:'#2a2a2a', textTransform:'uppercase', letterSpacing:1, marginBottom:3 }}>Path</div>
                <div style={{ fontSize:9, color:'#333', wordBreak:'break-all', fontFamily:'monospace' }}>{selected.path}</div>
              </div>
            )}

            {selected.cmdline && (
              <div style={{ marginBottom:12 }}>
                <div style={{ fontSize:9, color:'#2a2a2a', textTransform:'uppercase', letterSpacing:1, marginBottom:3 }}>Cmdline</div>
                <div style={{ fontSize:9, color:'#333', wordBreak:'break-all', fontFamily:'monospace', background:'#040404', padding:'4px 6px' }}>{selected.cmdline}</div>
              </div>
            )}

            {selected.suspicious && (
              <div style={{ padding:'6px 8px', background:'#1a0000', border:'1px solid #3d1520', marginBottom:12 }}>
                <div style={{ fontSize:9, color:'#e05c6e' }}>Suspicious indicators:</div>
                <div style={{ fontSize:9, color:'#c8a84b', marginTop:3 }}>
                  {selected.path.includes('\\Temp')||selected.path.includes('/tmp') ? '• Running from temp dir\n' : ''}
                  {selected.cmdline.includes('bypass')||selected.cmdline.includes('-enc') ? '• Suspicious PowerShell flags\n' : ''}
                  {selected.name.endsWith('s.exe')&&selected.name!=='services.exe'&&selected.name!=='smss.exe'&&selected.name!=='csrss.exe'&&selected.name!=='lsass.exe' ? '• Name mimics system process\n' : ''}
                  {selected.cmdline.includes('4444') ? '• C2-like port in cmdline' : ''}
                </div>
              </div>
            )}

            <div style={{ display:'flex', flexDirection:'column', gap:6 }}>
              <button onClick={()=>mark(selected.pid)} style={{ background:'#080808', border:'1px solid #1a1a1a', color:'#c8a84b', fontFamily:'Courier New', fontSize:10, padding:'5px', cursor:'pointer' }}>
                {selected.marked?'UNMARK':'MARK SUSPICIOUS'}
              </button>
              <button style={{ background:'#080808', border:'1px solid #1a1a1a', color:'#5a96d4', fontFamily:'Courier New', fontSize:10, padding:'5px', cursor:'pointer' }}>
                INJECT SHELLCODE
              </button>
              <button style={{ background:'#080808', border:'1px solid #1a1a1a', color:'#a07fd4', fontFamily:'Courier New', fontSize:10, padding:'5px', cursor:'pointer' }}>
                MIGRATE (SPAWN)
              </button>
              <button onClick={()=>{ kill(selected.pid); setSelected(null); }} style={{ background:'#1a0000', border:'1px solid #3d1520', color:'#e05c6e', fontFamily:'Courier New', fontSize:10, padding:'5px', cursor:'pointer' }}>
                KILL PROCESS
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
