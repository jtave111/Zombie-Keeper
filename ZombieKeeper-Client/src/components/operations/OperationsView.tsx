import { useState } from 'react';

type Phase = 'planned'|'active'|'done'|'blocked';
interface OpTask {
  id: string; title: string; phase: Phase; agent: string;
  tags: string[]; priority: 'low'|'med'|'high'|'critical';
  desc: string; ts: string;
}

const PHASES: { key:Phase; label:string; color:string }[] = [
  { key:'planned', label:'PLANNED',    color:'#5a96d4' },
  { key:'active',  label:'EXECUTING',  color:'#d48b55' },
  { key:'done',    label:'COMPLETED',  color:'#33a84a' },
  { key:'blocked', label:'BLOCKED',    color:'#e05c6e' },
];

const PRIO_COL: Record<string,string> = { low:'#2a2a2a', med:'#c8a84b', high:'#d48b55', critical:'#e05c6e' };

const INIT_TASKS: OpTask[] = [
  { id:'OP-001', title:'Domain Recon — AD Enum',        phase:'done',    agent:'ZK-001', tags:['recon','AD'],       priority:'high',     desc:'Enumerate AD users, groups, GPOs via LDAP.', ts:'02:14' },
  { id:'OP-002', title:'Kerberoasting — SPN Accounts',  phase:'done',    agent:'ZK-001', tags:['cred','kerberos'],  priority:'critical', desc:'Request TGS for all SPN accounts.', ts:'02:31' },
  { id:'OP-003', title:'Lateral — WIN-EXCH01',           phase:'active',  agent:'ZK-003', tags:['lateral','SMB'],   priority:'high',     desc:'Pass-the-hash to Exchange server via SMB.', ts:'03:12' },
  { id:'OP-004', title:'Dump LSASS — ZK-005',            phase:'active',  agent:'ZK-005', tags:['cred','LSASS'],    priority:'critical', desc:'Minidump LSASS via comsvcs.dll.', ts:'03:28' },
  { id:'OP-005', title:'Establish Persistence — WMI',    phase:'planned', agent:'ZK-001', tags:['persist','WMI'],   priority:'high',     desc:'WMI subscription for persistent beacon.', ts:'—' },
  { id:'OP-006', title:'SOCKS Tunnel — CENTOS-DB',       phase:'planned', agent:'ZK-002', tags:['pivot','SOCKS5'],  priority:'med',      desc:'Open SOCKS5 proxy through web server.', ts:'—' },
  { id:'OP-007', title:'Exfil — Financial Reports',      phase:'planned', agent:'ZK-005', tags:['exfil','HTTPS'],   priority:'critical', desc:'Stage and exfil /finance share over HTTPS.', ts:'—' },
  { id:'OP-008', title:'UAC Bypass — WIN-WS03',          phase:'blocked', agent:'ZK-003', tags:['privesc','UAC'],   priority:'high',     desc:'fodhelper bypass — AV detected previous attempt.', ts:'02:58' },
];

export default function OperationsView() {
  const [tasks, setTasks] = useState<OpTask[]>(INIT_TASKS);
  const [adding, setAdding] = useState<Phase|null>(null);
  const [newTitle, setNewTitle] = useState('');
  const [selected, setSelected] = useState<OpTask|null>(null);

  const move = (id:string, to:Phase) =>
    setTasks(p => p.map(t => t.id===id ? {...t,phase:to} : t));

  const addTask = (phase: Phase) => {
    if (!newTitle.trim()) return;
    setTasks(p => [...p, {
      id:`OP-${String(p.length+1).padStart(3,'0')}`, title:newTitle, phase,
      agent:'—', tags:[], priority:'med', desc:'', ts:'—',
    }]);
    setNewTitle(''); setAdding(null);
  };

  return (
    <div style={{ display:'flex', flexDirection:'column', height:'100%', overflow:'hidden', fontFamily:'Courier New' }}>

      {/* Header */}
      <div style={{ padding:'8px 14px', background:'var(--inset2)', borderBottom:'1px solid #1a1a1a', display:'flex', alignItems:'center', gap:16, flexShrink:0 }}>
        <span style={{ fontSize:11, color:'var(--tx1)', textTransform:'uppercase', letterSpacing:1 }}>Operation Planner</span>
        <div style={{ display:'flex', gap:10 }}>
          {PHASES.map(ph => (
            <span key={ph.key} style={{ fontSize:10, color:ph.color }}>
              {ph.label}: {tasks.filter(t=>t.phase===ph.key).length}
            </span>
          ))}
        </div>
        <span style={{ marginLeft:'auto', fontSize:9, color:'var(--tx2)' }}>drag planned → use move buttons</span>
      </div>

      {/* Board */}
      <div style={{ flex:1, overflow:'hidden', display:'flex', gap:8, padding:'10px 14px' }}>
        {PHASES.map(ph => (
          <div key={ph.key} style={{ flex:1, display:'flex', flexDirection:'column', overflow:'hidden', background:'var(--inset2)', border:'1px solid #1a1a1a' }}>
            {/* Lane header */}
            <div style={{ padding:'6px 10px', background:'var(--inset)', borderBottom:'1px solid #1a1a1a', display:'flex', alignItems:'center', gap:8, flexShrink:0 }}>
              <div style={{ width:4, height:4, borderRadius:'50%', background:ph.color }}/>
              <span style={{ fontSize:9, color:ph.color, textTransform:'uppercase', letterSpacing:1.2, fontWeight:700 }}>{ph.label}</span>
              <span style={{ fontSize:9, color:'var(--tx2)', marginLeft:'auto' }}>{tasks.filter(t=>t.phase===ph.key).length}</span>
            </div>

            {/* Cards */}
            <div style={{ flex:1, overflowY:'auto', padding:'8px' }}>
              {tasks.filter(t=>t.phase===ph.key).map(t => (
                <div key={t.id}
                  onClick={()=>setSelected(selected?.id===t.id?null:t)}
                  style={{
                    background: selected?.id===t.id ? '#111' : '#0d0d0d',
                    border:`1px solid ${selected?.id===t.id ? ph.color+'66' : '#1a1a1a'}`,
                    padding:'8px 10px', marginBottom:6, cursor:'pointer',
                  }}>
                  <div style={{ display:'flex', justifyContent:'space-between', marginBottom:4 }}>
                    <span style={{ fontSize:9, color:PRIO_COL[t.priority], textTransform:'uppercase', letterSpacing:0.5 }}>
                      ▲ {t.priority}
                    </span>
                    <span style={{ fontSize:9, color:'var(--tx2)' }}>{t.ts}</span>
                  </div>
                  <div style={{ fontSize:11, color:'#cccccc', lineHeight:1.4, marginBottom:4 }}>{t.title}</div>
                  <div style={{ display:'flex', gap:4, flexWrap:'wrap', marginBottom:4 }}>
                    {t.tags.map(tag => (
                      <span key={tag} style={{ fontSize:8, padding:'1px 5px', background:'var(--inset)', color:'var(--tx2)', border:'1px solid #222' }}>{tag}</span>
                    ))}
                  </div>
                  <div style={{ fontSize:9, color:'var(--tx2)' }}>{t.agent !== '—' ? `→ ${t.agent}` : ''}</div>

                  {/* Move buttons */}
                  {selected?.id===t.id && (
                    <div style={{ display:'flex', gap:4, marginTop:6, flexWrap:'wrap' }}>
                      {PHASES.filter(p=>p.key!==ph.key).map(p => (
                        <button key={p.key} onClick={e=>{e.stopPropagation();move(t.id,p.key);}} style={{
                          background:'var(--inset2)', border:`1px solid ${p.color}44`,
                          color:p.color, fontFamily:'Courier New', fontSize:8,
                          padding:'2px 8px', cursor:'pointer', textTransform:'uppercase',
                        }}>→ {p.label}</button>
                      ))}
                    </div>
                  )}
                </div>
              ))}

              {/* Add task */}
              {adding === ph.key ? (
                <div style={{ background:'var(--inset2)', border:'1px solid #1a1a1a', padding:'8px' }}>
                  <input autoFocus value={newTitle} onChange={e=>setNewTitle(e.target.value)}
                    onKeyDown={e=>{ if(e.key==='Enter') addTask(ph.key); if(e.key==='Escape') setAdding(null); }}
                    placeholder="task title..."
                    style={{ width:'100%', background:'var(--inset2)', border:'1px solid #2a2a2a', color:'#ccc', fontFamily:'Courier New', fontSize:11, padding:'4px 8px', outline:'none', marginBottom:4 }}/>
                  <div style={{ display:'flex', gap:4 }}>
                    <button onClick={()=>addTask(ph.key)} style={{ background:'#1a0000', border:'1px solid #e05c6e', color:'#e05c6e', fontFamily:'Courier New', fontSize:9, padding:'2px 10px', cursor:'pointer' }}>ADD</button>
                    <button onClick={()=>setAdding(null)} style={{ background:'transparent', border:'1px solid #222', color:'var(--tx2)', fontFamily:'Courier New', fontSize:9, padding:'2px 10px', cursor:'pointer' }}>CANCEL</button>
                  </div>
                </div>
              ) : (
                <button onClick={()=>setAdding(ph.key)} style={{ width:'100%', background:'transparent', border:'1px dashed #1a1a1a', color:'var(--tx2)', fontFamily:'Courier New', fontSize:10, padding:'6px', cursor:'pointer', marginTop:2 }}>
                  + add task
                </button>
              )}
            </div>
          </div>
        ))}
      </div>

      {/* Detail panel */}
      {selected && (
        <div style={{ padding:'8px 14px', background:'var(--inset2)', borderTop:'1px solid #1a1a1a', flexShrink:0 }}>
          <span style={{ fontSize:10, color:'#e05c6e', marginRight:12 }}>{selected.id}</span>
          <span style={{ fontSize:10, color:'#777' }}>{selected.desc || 'no description'}</span>
        </div>
      )}
    </div>
  );
}
