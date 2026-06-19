import { useState } from 'react';

type ArtifactType = 'file'|'registry'|'process'|'service'|'network'|'log';
type CleanStatus  = 'dirty'|'cleaning'|'clean'|'verified';

interface Artifact {
  id: string; host: string; agent: string; type: ArtifactType;
  path: string; detail: string; ts: string;
  clean: CleanStatus; risk: 'low'|'med'|'high'|'critical';
}

const RISK_COL: Record<string,string> = { low:'#2a2a2a', med:'#c8a84b', high:'#d48b55', critical:'#e05c6e' };
const CLEAN_COL: Record<CleanStatus,string> = { dirty:'#e05c6e', cleaning:'#d48b55', clean:'#33a84a', verified:'#5a96d4' };
const TYPE_ICON: Record<ArtifactType,string> = { file:'f', registry:'r', process:'p', service:'s', network:'n', log:'l' };

const INIT: Artifact[] = [
  {id:'IOC-001',host:'WIN-DC01',  agent:'ZK-001',type:'file',    path:'C:\\Windows\\Temp\\svchosts.exe',    detail:'Dropped beacon binary',                    ts:'02:14',clean:'dirty',   risk:'critical'},
  {id:'IOC-002',host:'WIN-DC01',  agent:'ZK-001',type:'registry',path:'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Update', detail:'Persistence key added', ts:'02:31',clean:'dirty',   risk:'critical'},
  {id:'IOC-003',host:'WIN-DC01',  agent:'ZK-001',type:'log',     path:'Windows Security Log',              detail:'4625 failed logon x47 — brute force',      ts:'02:18',clean:'dirty',   risk:'high'},
  {id:'IOC-004',host:'UBUNTU-WEB',agent:'ZK-002',type:'file',    path:'/tmp/.update',                      detail:'Cron persistence script',                  ts:'02:44',clean:'clean',   risk:'high'},
  {id:'IOC-005',host:'UBUNTU-WEB',agent:'ZK-002',type:'file',    path:'/tmp/linpeas.sh',                   detail:'PrivEsc enum script',                      ts:'02:47',clean:'verified',risk:'med'},
  {id:'IOC-006',host:'UBUNTU-WEB',agent:'ZK-002',type:'network', path:'0.0.0.0:1080',                      detail:'SOCKS5 proxy listener',                    ts:'02:44',clean:'dirty',   risk:'high'},
  {id:'IOC-007',host:'WIN-WS03',  agent:'ZK-003',type:'process', path:'lsass.exe (accessed)',              detail:'Minidump via comsvcs.dll',                  ts:'03:15',clean:'dirty',   risk:'critical'},
  {id:'IOC-008',host:'WIN-WS03',  agent:'ZK-003',type:'file',    path:'C:\\Users\\user\\AppData\\sam.bak', detail:'SAM hive copy',                            ts:'03:16',clean:'cleaning',risk:'critical'},
  {id:'IOC-009',host:'WIN-EXCH01',agent:'ZK-005',type:'service', path:'WinUpdate (svc)',                   detail:'Malicious service installed for persistence',ts:'03:05',clean:'dirty',  risk:'critical'},
  {id:'IOC-010',host:'WIN-EXCH01',agent:'ZK-005',type:'log',     path:'Application Event Log',             detail:'Error 1000 — crash from inject attempt',   ts:'02:58',clean:'dirty',   risk:'med'},
];

const OPSEC_SCORE = (arts: Artifact[]) => {
  const dirty = arts.filter(a=>a.clean==='dirty').length;
  const total = arts.length;
  return Math.round(((total - dirty) / total) * 100);
};

export default function OpsecView() {
  const [arts,      setArts]      = useState<Artifact[]>(INIT);
  const [filter,    setFilter]    = useState<'all'|ArtifactType|CleanStatus>('all');
  const [hostFilter,setHostFilter]= useState('all');
  const [selected,  setSelected]  = useState<Artifact|null>(null);

  const hosts = ['all', ...Array.from(new Set(INIT.map(a=>a.host)))];

  const visible = arts.filter(a => {
    const matchHost = hostFilter==='all' || a.host===hostFilter;
    const matchType = filter==='all' || a.type===filter || a.clean===filter;
    return matchHost && matchType;
  });

  const clean = (id: string) =>
    setArts(p => p.map(a => a.id!==id ? a : { ...a, clean: a.clean==='dirty'?'cleaning':a.clean==='cleaning'?'clean':a.clean==='clean'?'verified':a.clean }));

  const cleanAll = () =>
    setArts(p => p.map(a => visible.find(v=>v.id===a.id) ? {...a,clean:'cleaning'} : a));

  const score = OPSEC_SCORE(arts);
  const dirty = arts.filter(a=>a.clean==='dirty').length;

  return (
    <div style={{ display:'flex', flexDirection:'column', height:'100%', overflow:'hidden', fontFamily:'Courier New' }}>

      {/* Header / score */}
      <div style={{ padding:'8px 14px', background:'#0d0d0d', borderBottom:'1px solid #1a1a1a', display:'flex', alignItems:'center', gap:20, flexShrink:0 }}>
        <span style={{ fontSize:11, color:'#555', textTransform:'uppercase', letterSpacing:1 }}>OPSEC / IOC Tracker</span>

        {/* Score gauge */}
        <div style={{ display:'flex', alignItems:'center', gap:8 }}>
          <span style={{ fontSize:9, color:'#333', textTransform:'uppercase', letterSpacing:1 }}>OPSEC Score</span>
          <div style={{ width:80, height:6, background:'#111', borderRadius:3 }}>
            <div style={{ height:'100%', width:`${score}%`, background: score>75?'#33a84a':score>40?'#d48b55':'#e05c6e', borderRadius:3, transition:'width 0.3s' }}/>
          </div>
          <span style={{ fontSize:11, color: score>75?'#33a84a':score>40?'#d48b55':'#e05c6e', fontWeight:700 }}>{score}%</span>
        </div>

        <div style={{ display:'flex', gap:12 }}>
          <span style={{ fontSize:10, color:'#e05c6e' }}>dirty: {arts.filter(a=>a.clean==='dirty').length}</span>
          <span style={{ fontSize:10, color:'#d48b55' }}>cleaning: {arts.filter(a=>a.clean==='cleaning').length}</span>
          <span style={{ fontSize:10, color:'#33a84a' }}>clean: {arts.filter(a=>a.clean==='clean').length}</span>
          <span style={{ fontSize:10, color:'#5a96d4' }}>verified: {arts.filter(a=>a.clean==='verified').length}</span>
        </div>

        {dirty > 0 && (
          <button onClick={cleanAll} style={{ marginLeft:'auto', background:'#1a0000', border:'1px solid #e05c6e', color:'#e05c6e', fontFamily:'Courier New', fontSize:10, padding:'3px 14px', cursor:'pointer' }}>
            [ CLEAN VISIBLE ({visible.filter(a=>a.clean==='dirty').length}) ]
          </button>
        )}
      </div>

      {/* Filters */}
      <div style={{ padding:'5px 14px', background:'#0a0a0a', borderBottom:'1px solid #1a1a1a', display:'flex', gap:6, flexWrap:'wrap', flexShrink:0 }}>
        {/* Host filter */}
        <select value={hostFilter} onChange={e=>setHostFilter(e.target.value)}
          style={{ background:'#040404', border:'1px solid #1e1e1e', color:'#555', fontFamily:'Courier New', fontSize:10, padding:'2px 8px', outline:'none', appearance:'none' }}>
          {hosts.map(h=><option key={h}>{h}</option>)}
        </select>
        {/* Type/status filter */}
        {(['all','file','registry','process','service','network','log','dirty','clean','verified'] as const).map(f => (
          <button key={f} onClick={()=>setFilter(f)} style={{
            background: filter===f?'#181818':'transparent',
            border:`1px solid ${filter===f?'#333':'#1a1a1a'}`,
            color: filter===f?'#ccc':'#333',
            fontFamily:'Courier New', fontSize:9, padding:'2px 8px', cursor:'pointer', textTransform:'uppercase',
          }}>{f}</button>
        ))}
      </div>

      <div style={{ flex:1, display:'flex', overflow:'hidden' }}>

        {/* IOC list */}
        <div style={{ flex:1, overflowY:'auto' }}>
          <div style={{ display:'grid', gridTemplateColumns:'70px 30px 100px 70px 1fr 70px 80px 80px', padding:'4px 14px', background:'#111', borderBottom:'1px solid #1a1a1a', fontSize:9, color:'#333', textTransform:'uppercase', letterSpacing:0.8, position:'sticky', top:0 }}>
            <span>ID</span><span>T</span><span>Host</span><span>Agent</span><span>Path / Detail</span><span>Risk</span><span>Status</span><span>Action</span>
          </div>
          {visible.map(a => (
            <div key={a.id}
              onClick={()=>setSelected(selected?.id===a.id?null:a)}
              style={{
                display:'grid', gridTemplateColumns:'70px 30px 100px 70px 1fr 70px 80px 80px',
                padding:'6px 14px', borderBottom:'1px solid #0d0d0d', cursor:'pointer', alignItems:'center',
                background: selected?.id===a.id?'#0d0d14':'transparent',
              }}>
              <span style={{ fontSize:9, color:'#444' }}>{a.id}</span>
              <span style={{ fontSize:10, color:'#555', fontWeight:700 }}>{TYPE_ICON[a.type]}</span>
              <span style={{ fontSize:10, color:'#777' }}>{a.host.replace('WIN-','').replace('UBUNTU-','')}</span>
              <span style={{ fontSize:10, color:'#444' }}>{a.agent}</span>
              <div>
                <div style={{ fontSize:10, color:'#555', overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap' }}>{a.path}</div>
                <div style={{ fontSize:9, color:'#2a2a2a' }}>{a.detail}</div>
              </div>
              <span style={{ fontSize:9, color:RISK_COL[a.risk], fontWeight:700, textTransform:'uppercase' }}>{a.risk}</span>
              <span style={{ fontSize:9, color:CLEAN_COL[a.clean], textTransform:'uppercase' }}>● {a.clean}</span>
              <button onClick={e=>{e.stopPropagation();clean(a.id);}} disabled={a.clean==='verified'} style={{
                background:'#080808',
                border:`1px solid ${a.clean==='verified'?'#111':'#1a2a1a'}`,
                color: a.clean==='verified'?'#1a1a1a':CLEAN_COL[a.clean],
                fontFamily:'Courier New', fontSize:9, padding:'2px 8px', cursor:a.clean==='verified'?'default':'pointer',
              }}>
                {a.clean==='dirty'?'CLEAN':a.clean==='cleaning'?'VERIFY':a.clean==='clean'?'CONFIRM':'✓ DONE'}
              </button>
            </div>
          ))}
        </div>

        {/* Risk summary sidebar */}
        <div style={{ width:180, background:'#0a0a0a', borderLeft:'1px solid #1a1a1a', padding:'10px', flexShrink:0, overflowY:'auto' }}>
          <div style={{ fontSize:9, color:'#2a2a2a', textTransform:'uppercase', letterSpacing:1, marginBottom:10 }}>Risk by Host</div>
          {hosts.filter(h=>h!=='all').map(h => {
            const hArts = arts.filter(a=>a.host===h);
            const hDirty = hArts.filter(a=>a.clean==='dirty');
            const hCrit  = hArts.filter(a=>a.risk==='critical'&&a.clean==='dirty');
            return (
              <div key={h} style={{ marginBottom:10, padding:'6px 8px', background:'#0d0d0d', border:`1px solid ${hCrit.length>0?'#3a1220':'#1a1a1a'}` }}>
                <div style={{ fontSize:10, color: hCrit.length>0?'#e05c6e':'#555', marginBottom:3, fontWeight:700 }}>{h.split('-')[1]||h}</div>
                <div style={{ fontSize:9, color:'#333' }}>{hDirty.length}/{hArts.length} unclean</div>
                {hCrit.length>0&&<div style={{ fontSize:9, color:'#e05c6e', marginTop:2 }}>{hCrit.length} critical!</div>}
                <div style={{ height:3, background:'#111', marginTop:4, borderRadius:2 }}>
                  <div style={{ height:'100%', width:`${((hArts.length-hDirty.length)/hArts.length)*100}%`, background:'#33a84a', borderRadius:2 }}/>
                </div>
              </div>
            );
          })}

          <div style={{ marginTop:14, fontSize:9, color:'#2a2a2a', textTransform:'uppercase', letterSpacing:1, marginBottom:8 }}>Exposure</div>
          {(['critical','high','med','low'] as const).map(r => {
            const count = arts.filter(a=>a.risk===r&&a.clean==='dirty').length;
            return count > 0 ? (
              <div key={r} style={{ display:'flex', justifyContent:'space-between', marginBottom:5, fontSize:10 }}>
                <span style={{ color:RISK_COL[r], textTransform:'uppercase' }}>{r}</span>
                <span style={{ color:RISK_COL[r] }}>{count}</span>
              </div>
            ) : null;
          })}
        </div>
      </div>

      {/* Detail bar */}
      {selected && (
        <div style={{ padding:'6px 14px', background:'#0d0d0d', borderTop:'1px solid #1a1a1a', flexShrink:0, display:'flex', gap:16, fontSize:10 }}>
          <span style={{ color:'#e05c6e' }}>{selected.id}</span>
          <span style={{ color:'#777' }}>{selected.path}</span>
          <span style={{ color:'#333' }}>{selected.detail}</span>
          <span style={{ color:'#2a2a2a', marginLeft:'auto' }}>{selected.ts}</span>
        </div>
      )}
    </div>
  );
}
