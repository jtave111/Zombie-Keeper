import { useState } from 'react';

type TechStatus = 'none'|'planned'|'active'|'done';
const CYCLE: TechStatus[] = ['none','planned','active','done'];
const S_COLOR: Record<TechStatus,string> = { none:'#111', planned:'#1e1a00', active:'#1a0000', done:'#091609' };
const S_TEXT:  Record<TechStatus,string> = { none:'#2a2a2a', planned:'#c8a84b', active:'#e05c6e', done:'#33a84a' };
const S_LABEL: Record<TechStatus,string> = { none:'—', planned:'PLANNED', active:'ACTIVE', done:'DONE' };

const MATRIX: { id:string; tactic:string; techniques:{ id:string; name:string }[] }[] = [
  { id:'TA0043', tactic:'Reconnaissance', techniques:[
    {id:'T1595',name:'Active Scanning'},{id:'T1592',name:'Host Information'},{id:'T1589',name:'Identity Info'},
    {id:'T1596',name:'Search Tech DBs'},{id:'T1593',name:'Search Websites'},{id:'T1598',name:'Phishing for Info'},
  ]},
  { id:'TA0001', tactic:'Initial Access', techniques:[
    {id:'T1190',name:'Exploit Public App'},{id:'T1566',name:'Phishing'},{id:'T1078',name:'Valid Accounts'},
    {id:'T1133',name:'External Remote Svc'},{id:'T1091',name:'Removable Media'},{id:'T1195',name:'Supply Chain'},
  ]},
  { id:'TA0002', tactic:'Execution', techniques:[
    {id:'T1059',name:'Cmd/Script Interpreter'},{id:'T1053',name:'Scheduled Task/Job'},{id:'T1047',name:'WMI'},
    {id:'T1204',name:'User Execution'},{id:'T1072',name:'Software Deployment'},{id:'T1106',name:'Native API'},
  ]},
  { id:'TA0003', tactic:'Persistence', techniques:[
    {id:'T1543',name:'Create/Modify Svc'},{id:'T1547',name:'Boot Autostart'},{id:'T1136',name:'Create Account'},
    {id:'T1053',name:'Scheduled Task'},{id:'T1505',name:'Server Software'},{id:'T1098',name:'Account Manip.'},
  ]},
  { id:'TA0004', tactic:'Privilege Escalation', techniques:[
    {id:'T1548',name:'Abuse Elevation Ctrl'},{id:'T1134',name:'Token Manipulation'},{id:'T1068',name:'Exploit for PrivEsc'},
    {id:'T1055',name:'Process Injection'},{id:'T1078',name:'Valid Accounts'},{id:'T1574',name:'Hijack Exec Flow'},
  ]},
  { id:'TA0005', tactic:'Defense Evasion', techniques:[
    {id:'T1562',name:'Impair Defenses'},{id:'T1055',name:'Process Injection'},{id:'T1036',name:'Masquerading'},
    {id:'T1112',name:'Modify Registry'},{id:'T1027',name:'Obfuscated Files'},{id:'T1070',name:'Indicator Removal'},
  ]},
  { id:'TA0006', tactic:'Credential Access', techniques:[
    {id:'T1003',name:'OS Credential Dump'},{id:'T1110',name:'Brute Force'},{id:'T1558',name:'Kerberoasting'},
    {id:'T1555',name:'Creds from Stores'},{id:'T1040',name:'Network Sniffing'},{id:'T1539',name:'Web Session Cookie'},
  ]},
  { id:'TA0007', tactic:'Discovery', techniques:[
    {id:'T1082',name:'System Info'},{id:'T1046',name:'Network Scan'},{id:'T1083',name:'File/Dir Discovery'},
    {id:'T1069',name:'Permission Groups'},{id:'T1057',name:'Process Discovery'},{id:'T1016',name:'Net Config'},
  ]},
  { id:'TA0008', tactic:'Lateral Movement', techniques:[
    {id:'T1021',name:'Remote Services'},{id:'T1550',name:'Pass the Hash'},{id:'T1570',name:'Lateral Tool Xfer'},
    {id:'T1563',name:'Remote Svc Session'},{id:'T1534',name:'Internal Phishing'},{id:'T1080',name:'Taint Shared'},
  ]},
  { id:'TA0009', tactic:'Collection', techniques:[
    {id:'T1005',name:'Data from Local Sys'},{id:'T1056',name:'Input Capture'},{id:'T1113',name:'Screen Capture'},
    {id:'T1119',name:'Automated Collection'},{id:'T1115',name:'Clipboard Data'},{id:'T1185',name:'Browser Data'},
  ]},
  { id:'TA0011', tactic:'C&C', techniques:[
    {id:'T1071',name:'App Layer Protocol'},{id:'T1573',name:'Encrypted Channel'},{id:'T1008',name:'Fallback Channels'},
    {id:'T1090',name:'Proxy'},{id:'T1095',name:'Non-App Layer Proto'},{id:'T1102',name:'Web Service'},
  ]},
  { id:'TA0010', tactic:'Exfiltration', techniques:[
    {id:'T1041',name:'Exfil Over C2'},{id:'T1048',name:'Exfil Alt Protocol'},{id:'T1567',name:'Exfil Web Svc'},
    {id:'T1029',name:'Scheduled Transfer'},{id:'T1030',name:'Data Size Limits'},{id:'T1020',name:'Automated Exfil'},
  ]},
  { id:'TA0040', tactic:'Impact', techniques:[
    {id:'T1485',name:'Data Destruction'},{id:'T1486',name:'Data Encrypted'},{id:'T1489',name:'Service Stop'},
    {id:'T1490',name:'Inhibit Recovery'},{id:'T1499',name:'Endpoint Denial'},{id:'T1496',name:'Resource Hijack'},
  ]},
];

export default function MitreView() {
  const [techs, setTechs] = useState<Record<string,TechStatus>>({});
  const [filter, setFilter] = useState<TechStatus|'all'>('all');
  const [detail, setDetail] = useState<{id:string;name:string;tactic:string}|null>(null);

  const cycle = (id: string) =>
    setTechs(p => {
      const cur = p[id] || 'none';
      const next = CYCLE[(CYCLE.indexOf(cur)+1) % CYCLE.length];
      return { ...p, [id]: next };
    });

  const counts = {
    done:    Object.values(techs).filter(s=>s==='done').length,
    active:  Object.values(techs).filter(s=>s==='active').length,
    planned: Object.values(techs).filter(s=>s==='planned').length,
  };

  return (
    <div style={{ display:'flex', flexDirection:'column', height:'100%', overflow:'hidden', fontFamily:'Courier New' }}>

      {/* Header */}
      <div style={{ padding:'8px 14px', background:'#0d0d0d', borderBottom:'1px solid #1a1a1a', display:'flex', alignItems:'center', gap:20, flexShrink:0 }}>
        <span style={{ fontSize:11, color:'#555', textTransform:'uppercase', letterSpacing:1 }}>MITRE ATT&amp;CK — Enterprise</span>
        <div style={{ display:'flex', gap:12 }}>
          {(['done','active','planned'] as const).map(s => (
            <span key={s} style={{ fontSize:10, color:S_TEXT[s] }}>
              {S_LABEL[s]}: {counts[s]}
            </span>
          ))}
        </div>
        <div style={{ marginLeft:'auto', display:'flex', gap:6 }}>
          {(['all','planned','active','done'] as const).map(f => (
            <button key={f} onClick={()=>setFilter(f)} style={{
              background: filter===f ? (f==='all'?'#181818':S_COLOR[f as TechStatus]) : '#080808',
              border:`1px solid ${filter===f?(f==='all'?'#333':S_TEXT[f as TechStatus]):'#1a1a1a'}`,
              color: filter===f ? (f==='all'?'#888':S_TEXT[f as TechStatus]) : '#2a2a2a',
              fontFamily:'Courier New', fontSize:9, padding:'2px 10px', cursor:'pointer', textTransform:'uppercase',
            }}>{f}</button>
          ))}
          <button onClick={()=>setTechs({})} style={{ background:'#080808', border:'1px solid #1a1a1a', color:'#333', fontFamily:'Courier New', fontSize:9, padding:'2px 10px', cursor:'pointer' }}>RESET</button>
        </div>
      </div>

      {/* Matrix */}
      <div style={{ flex:1, overflowX:'auto', overflowY:'auto' }}>
        <div style={{ display:'flex', minWidth:'max-content', padding:'10px 14px', gap:6, alignItems:'flex-start' }}>
          {MATRIX.map(col => (
            <div key={col.id} style={{ width:130, flexShrink:0 }}>
              <div style={{ background:'#181818', border:'1px solid #222', padding:'5px 7px', marginBottom:4 }}>
                <div style={{ fontSize:8, color:'#e05c6e', letterSpacing:1, textTransform:'uppercase', marginBottom:1 }}>{col.id}</div>
                <div style={{ fontSize:10, color:'#888', fontWeight:700, lineHeight:1.3 }}>{col.tactic}</div>
              </div>
              {col.techniques.map(t => {
                const st = techs[t.id] || 'none';
                if (filter !== 'all' && st !== filter) return (
                  <div key={t.id} style={{ height:40, background:'#080808', border:'1px solid #0d0d0d', marginBottom:3, opacity:0.15 }}/>
                );
                return (
                  <div key={t.id} onClick={()=>{cycle(t.id); setDetail({...t, tactic:col.tactic});}}
                    style={{
                      background:S_COLOR[st], border:`1px solid ${st==='none'?'#1a1a1a':S_TEXT[st]+'44'}`,
                      padding:'5px 7px', marginBottom:3, cursor:'pointer', minHeight:40,
                      transition:'all 0.1s',
                    }}
                    onMouseEnter={e=>(e.currentTarget.style.borderColor=S_TEXT[st])}
                    onMouseLeave={e=>(e.currentTarget.style.borderColor=st==='none'?'#1a1a1a':S_TEXT[st]+'44')}>
                    <div style={{ fontSize:8, color:S_TEXT[st]==='#2a2a2a'?'#2a2a2a':S_TEXT[st]+'99', letterSpacing:0.5 }}>{t.id}</div>
                    <div style={{ fontSize:9, color:st==='none'?'#2a2a2a':S_TEXT[st], lineHeight:1.3, marginTop:1 }}>{t.name}</div>
                  </div>
                );
              })}
            </div>
          ))}
        </div>
      </div>

      {/* Detail bar */}
      {detail && (
        <div style={{ padding:'6px 14px', background:'#0d0d0d', borderTop:'1px solid #1a1a1a', display:'flex', gap:16, alignItems:'center', flexShrink:0, fontSize:10 }}>
          <span style={{ color:'#e05c6e' }}>{detail.id}</span>
          <span style={{ color:'#777' }}>{detail.name}</span>
          <span style={{ color:'#333' }}>{detail.tactic}</span>
          <span style={{ color:S_TEXT[techs[detail.id]||'none'], marginLeft:'auto' }}>{S_LABEL[techs[detail.id]||'none']}</span>
          <span style={{ color:'#2a2a2a' }}>click technique to cycle status</span>
        </div>
      )}
    </div>
  );
}
