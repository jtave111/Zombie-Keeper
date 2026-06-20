import { useState } from 'react';

type TunnelType = 'SOCKS5'|'TCP-FWD'|'REV-FWD'|'DNS-TUNNEL';
type TunnelStatus = 'ACTIVE'|'BROKEN'|'PENDING'|'STOPPED';

interface Tunnel {
  id: string; type: TunnelType; status: TunnelStatus;
  agent: string; host: string;
  localPort: number; remoteHost: string; remotePort: number;
  bytes: string; conns: number; created: string;
}

const STATUS_COLOR: Record<TunnelStatus,string> = {
  ACTIVE:'#33a84a', BROKEN:'#e05c6e', PENDING:'#d48b55', STOPPED:'#2a2a2a',
};

const INIT: Tunnel[] = [
  { id:'TUN-001', type:'SOCKS5',   status:'ACTIVE',  agent:'ZK-002', host:'UBUNTU-WEB',  localPort:1080, remoteHost:'',              remotePort:0,    bytes:'4.2 MB',  conns:12, created:'02:44' },
  { id:'TUN-002', type:'TCP-FWD',  status:'ACTIVE',  agent:'ZK-003', host:'WIN-WS03',    localPort:3389, remoteHost:'192.168.5.50',  remotePort:3389, bytes:'812 KB',  conns:1,  created:'03:01' },
  { id:'TUN-003', type:'REV-FWD',  status:'PENDING', agent:'ZK-005', host:'WIN-EXCH01',  localPort:8443, remoteHost:'10.10.10.20',   remotePort:445,  bytes:'0 B',     conns:0,  created:'03:30' },
  { id:'TUN-004', type:'DNS-TUNNEL',status:'BROKEN',  agent:'ZK-001', host:'WIN-DC01',    localPort:53,   remoteHost:'exfil.c2.local',remotePort:53,   bytes:'128 KB',  conns:3,  created:'01:15' },
];

const TYPE_COLOR: Record<TunnelType,string> = {
  'SOCKS5':'#5a96d4', 'TCP-FWD':'#c8a84b', 'REV-FWD':'#a07fd4', 'DNS-TUNNEL':'#d48b55',
};

export default function TunnelsView() {
  const [tunnels,  setTunnels]  = useState<Tunnel[]>(INIT);
  const [creating, setCreating] = useState(false);
  const [form,     setForm]     = useState({ type:'SOCKS5' as TunnelType, agent:'ZK-002', localPort:'1081', remoteHost:'', remotePort:'0' });

  const toggle = (id: string) =>
    setTunnels(p => p.map(t => t.id!==id ? t : {
      ...t,
      status: t.status==='ACTIVE' ? 'STOPPED' : t.status==='STOPPED' ? 'PENDING' : t.status,
    }));

  const destroy = (id: string) => setTunnels(p => p.filter(t=>t.id!==id));

  const create = () => {
    setTunnels(p => [...p, {
      id:`TUN-${String(p.length+1).padStart(3,'0')}`,
      type:form.type, status:'PENDING',
      agent:form.agent, host:'...',
      localPort:+form.localPort, remoteHost:form.remoteHost, remotePort:+form.remotePort,
      bytes:'0 B', conns:0, created:'now',
    }]);
    setCreating(false);
  };

  // Chain ASCII diagram
  const activeChain = tunnels.filter(t=>t.status==='ACTIVE');

  return (
    <div style={{ display:'flex', flexDirection:'column', height:'100%', overflow:'hidden', fontFamily:'Courier New' }}>

      {/* Header */}
      <div style={{ padding:'8px 14px', background:'var(--inset2)', borderBottom:'1px solid #1a1a1a', display:'flex', alignItems:'center', gap:16, flexShrink:0 }}>
        <span style={{ fontSize:11, color:'var(--tx1)', textTransform:'uppercase', letterSpacing:1 }}>Pivot &amp; Tunnel Manager</span>
        <div style={{ display:'flex', gap:12 }}>
          {(['ACTIVE','BROKEN','PENDING'] as TunnelStatus[]).map(s=>(
            <span key={s} style={{ fontSize:10, color:STATUS_COLOR[s] }}>
              {s}: {tunnels.filter(t=>t.status===s).length}
            </span>
          ))}
        </div>
        <button onClick={()=>setCreating(c=>!c)} style={{ marginLeft:'auto', background:'#1a0000', border:'1px solid #e05c6e', color:'#e05c6e', fontFamily:'Courier New', fontSize:10, padding:'3px 14px', cursor:'pointer' }}>
          {creating ? '[ CANCEL ]' : '[ + NEW TUNNEL ]'}
        </button>
      </div>

      {/* Create form */}
      {creating && (
        <div style={{ padding:'10px 14px', background:'var(--inset2)', borderBottom:'1px solid #1a1a1a', display:'flex', gap:10, alignItems:'flex-end', flexShrink:0 }}>
          {[
            { label:'Type',        el: <select value={form.type} onChange={e=>setForm(p=>({...p,type:e.target.value as TunnelType}))} style={{background:'var(--inset2)',border:'1px solid #1e1e1e',color:'#ccc',fontFamily:'Courier New',fontSize:11,padding:'4px 8px',outline:'none',appearance:'none'}}>
              {(['SOCKS5','TCP-FWD','REV-FWD','DNS-TUNNEL'] as TunnelType[]).map(t=><option key={t}>{t}</option>)}</select> },
            { label:'Agent',       el: <select value={form.agent} onChange={e=>setForm(p=>({...p,agent:e.target.value}))} style={{background:'var(--inset2)',border:'1px solid #1e1e1e',color:'#ccc',fontFamily:'Courier New',fontSize:11,padding:'4px 8px',outline:'none',appearance:'none'}}>
              {['ZK-001','ZK-002','ZK-003','ZK-005','ZK-006'].map(a=><option key={a}>{a}</option>)}</select> },
            { label:'Local Port',  el: <input value={form.localPort} onChange={e=>setForm(p=>({...p,localPort:e.target.value}))} style={{width:80,background:'var(--inset2)',border:'1px solid #1e1e1e',color:'#ccc',fontFamily:'Courier New',fontSize:11,padding:'4px 8px',outline:'none'}}/> },
            { label:'Remote Host', el: <input value={form.remoteHost} onChange={e=>setForm(p=>({...p,remoteHost:e.target.value}))} placeholder="192.168.x.x" style={{width:130,background:'var(--inset2)',border:'1px solid #1e1e1e',color:'#ccc',fontFamily:'Courier New',fontSize:11,padding:'4px 8px',outline:'none'}}/> },
            { label:'Remote Port', el: <input value={form.remotePort} onChange={e=>setForm(p=>({...p,remotePort:e.target.value}))} style={{width:80,background:'var(--inset2)',border:'1px solid #1e1e1e',color:'#ccc',fontFamily:'Courier New',fontSize:11,padding:'4px 8px',outline:'none'}}/> },
          ].map(({label,el})=>(
            <div key={label}>
              <div style={{fontSize:9,color:'var(--tx2)',textTransform:'uppercase',letterSpacing:1,marginBottom:3}}>{label}</div>
              {el}
            </div>
          ))}
          <button onClick={create} style={{ background:'#1a0000', border:'1px solid #e05c6e', color:'#e05c6e', fontFamily:'Courier New', fontSize:11, padding:'4px 16px', cursor:'pointer' }}>CREATE</button>
        </div>
      )}

      <div style={{ flex:1, display:'flex', overflow:'hidden' }}>

        {/* Tunnel list */}
        <div style={{ flex:1, overflowY:'auto' }}>
          {/* Table header */}
          <div style={{ display:'grid', gridTemplateColumns:'80px 90px 80px 100px 120px 90px 70px 70px 80px', padding:'4px 14px', background:'var(--inset)', borderBottom:'1px solid #1a1a1a', fontSize:9, color:'var(--tx2)', textTransform:'uppercase', letterSpacing:0.8, flexShrink:0, position:'sticky', top:0 }}>
            <span>ID</span><span>Type</span><span>Status</span><span>Agent</span><span>Binding</span><span>Remote</span><span>Bytes</span><span>Conns</span><span/>
          </div>
          {tunnels.map(t => (
            <div key={t.id} style={{ display:'grid', gridTemplateColumns:'80px 90px 80px 100px 120px 90px 70px 70px 80px', padding:'7px 14px', borderBottom:'1px solid #0d0d0d', alignItems:'center' }}>
              <span style={{ fontSize:10, color:'var(--tx1)' }}>{t.id}</span>
              <span style={{ fontSize:9, color:TYPE_COLOR[t.type], fontWeight:700 }}>{t.type}</span>
              <span style={{ fontSize:9, color:STATUS_COLOR[t.status] }}>● {t.status}</span>
              <span style={{ fontSize:10, color:'#777' }}>{t.agent}</span>
              <span style={{ fontSize:10, color:'var(--tx2)', fontFamily:'monospace' }}>:{t.localPort}</span>
              <span style={{ fontSize:10, color:'var(--tx2)', fontFamily:'monospace' }}>{t.remoteHost ? `${t.remoteHost}:${t.remotePort}` : '—'}</span>
              <span style={{ fontSize:10, color:'var(--tx2)' }}>{t.bytes}</span>
              <span style={{ fontSize:10, color:'var(--tx2)' }}>{t.conns}</span>
              <div style={{ display:'flex', gap:4 }}>
                {t.status !== 'STOPPED' && (
                  <button onClick={()=>toggle(t.id)} style={{ background:'var(--inset2)', border:'1px solid #1a1a1a', color:t.status==='ACTIVE'?'#d48b55':'#33a84a', fontFamily:'Courier New', fontSize:9, padding:'2px 6px', cursor:'pointer' }}>
                    {t.status==='ACTIVE'?'STOP':'START'}
                  </button>
                )}
                <button onClick={()=>destroy(t.id)} style={{ background:'var(--inset2)', border:'1px solid #3d1520', color:'#e05c6e', fontFamily:'Courier New', fontSize:9, padding:'2px 6px', cursor:'pointer' }}>✕</button>
              </div>
            </div>
          ))}
        </div>

        {/* Chain diagram */}
        <div style={{ width:220, background:'var(--inset2)', borderLeft:'1px solid #1a1a1a', padding:'10px', overflow:'auto', flexShrink:0 }}>
          <div style={{ fontSize:9, color:'var(--tx2)', textTransform:'uppercase', letterSpacing:1, marginBottom:10 }}>Active Chain</div>
          <div style={{ fontFamily:'Courier New', fontSize:10, color:'var(--tx2)', lineHeight:2 }}>
            <div style={{ color:'#e05c6e' }}>[ C2 Server ]</div>
            {activeChain.map((t,i) => (
              <div key={t.id}>
                <div style={{ color:'var(--tx3)' }}>    │</div>
                <div style={{ color:'var(--tx1)' }}>{String.fromCharCode(9484)}{Array(3).fill('─').join('')}&gt; <span style={{ color:TYPE_COLOR[t.type] }}>{t.type}</span></div>
                <div style={{ color:'var(--tx1)' }}>│ {t.agent} :{t.localPort}</div>
                {i < activeChain.length-1 && <div style={{ color:'var(--tx3)' }}>│</div>}
              </div>
            ))}
            {activeChain.length === 0 && <div style={{ color:'var(--tx3)' }}>no active tunnels</div>}
            <div style={{ color:'var(--tx3)', marginTop:4 }}>    │</div>
            <div style={{ color:'var(--tx2)' }}>{String.fromCharCode(9492)}{Array(3).fill('─').join('')}&gt; TARGET</div>
          </div>
        </div>
      </div>
    </div>
  );
}
