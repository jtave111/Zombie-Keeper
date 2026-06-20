import { useState } from 'react';

interface Credential {
  id: number;
  host: string;
  port?: number;
  type: 'SSH Key' | 'Password' | 'Hash (NTLM)' | 'Hash (SHA256)' | 'API Key' | 'Token' | 'Certificate';
  username: string;
  secret: string;
  source: string;    // where it was found
  agentId: string;
  captured: string;
  verified: boolean;
  notes: string;
}

const MOCK_CREDS: Credential[] = [];

const TYPE_COL: Record<string, string> = {
  'SSH Key':       '#33a84a',
  'Password':      '#e05c6e',
  'Hash (NTLM)':   '#d48b55',
  'Hash (SHA256)': '#d48b55',
  'API Key':       '#5bb8d4',
  'Token':         '#a07fd4',
  'Certificate':   '#c8a84b',
};

export default function CredentialsView() {
  const [search,  setSearch]  = useState('');
  const [filter,  setFilter]  = useState<string>('ALL');
  const [selCred, setSelCred] = useState<Credential | null>(null);
  const [showSecret, setShowSecret] = useState(false);

  const types = ['ALL', ...Array.from(new Set(MOCK_CREDS.map(c=>c.type)))];
  const creds = MOCK_CREDS.filter(c => {
    const mf = filter === 'ALL' || c.type === filter;
    const ms = !search || [c.host,c.username,c.source,c.notes,c.agentId].some(v=>v.toLowerCase().includes(search.toLowerCase()));
    return mf && ms;
  });

  return (
    <div style={{ display:'flex', flexDirection:'column', height:'100%', overflow:'hidden', background:'var(--inset2)', fontFamily:'Courier New' }}>

      {/* STAT BAR */}
      <div style={{ display:'flex', gap:0, flexShrink:0, borderBottom:'1px solid #111' }}>
        {[
          { l:'Total Credentials', v:MOCK_CREDS.length,                             c:'#e8e8e8' },
          { l:'Verified',          v:MOCK_CREDS.filter(c=>c.verified).length,       c:'#33a84a' },
          { l:'Unverified',        v:MOCK_CREDS.filter(c=>!c.verified).length,      c:'#d48b55' },
          { l:'SSH Keys',          v:MOCK_CREDS.filter(c=>c.type==='SSH Key').length,     c:'#33a84a' },
          { l:'Passwords',         v:MOCK_CREDS.filter(c=>c.type==='Password').length,    c:'#e05c6e' },
          { l:'Hashes',            v:MOCK_CREDS.filter(c=>c.type.startsWith('Hash')).length, c:'#d48b55' },
          { l:'Tokens / Keys',     v:MOCK_CREDS.filter(c=>['API Key','Token'].includes(c.type)).length, c:'#5bb8d4' },
        ].map((s,i) => (
          <div key={i} style={{ flex:1, padding:'10px 14px', borderRight:'1px solid #111', background:'var(--inset2)' }}>
            <div style={{ fontSize:9, color:'var(--tx1)', textTransform:'uppercase', letterSpacing:'1px', marginBottom:5 }}>{s.l}</div>
            <div style={{ fontSize:20, fontWeight:700, color:s.c }}>{s.v}</div>
          </div>
        ))}
      </div>

      {/* TOOLBAR */}
      <div style={{ display:'flex', alignItems:'center', gap:8, padding:'6px 12px', background:'var(--inset2)', borderBottom:'1px solid #111', flexShrink:0 }}>
        <input value={search} onChange={e=>setSearch(e.target.value)} placeholder="search host, user, source..."
          style={{ width:280, background:'var(--inset2)', border:'1px solid #1a1a1a', color:'#e8e8e8', fontFamily:'Courier New', fontSize:12, padding:'5px 8px', outline:'none' }}/>
        <span style={{ color:'var(--tx3)' }}>|</span>
        {types.map(t => (
          <button key={t} onClick={()=>setFilter(t)} style={{
            background: filter===t?'#1a0000':'transparent', border:`1px solid ${filter===t?'#e05c6e':'#111'}`,
            color: filter===t?'#e05c6e':'#555', fontFamily:'Courier New', fontSize:10,
            padding:'4px 10px', cursor:'pointer', textTransform:'uppercase',
          }}>{t}</button>
        ))}
        <div style={{ marginLeft:'auto', display:'flex', gap:6 }}>
          <button style={{ background:'transparent', border:'1px solid #111', color:'#777', fontFamily:'Courier New', fontSize:10, padding:'4px 10px', cursor:'pointer' }}>Export CSV</button>
          <button style={{ background:'#1a0000', border:'1px solid #e05c6e', color:'#e05c6e', fontFamily:'Courier New', fontSize:10, padding:'4px 10px', cursor:'pointer' }}>+ Add Manual</button>
        </div>
      </div>

      <div style={{ flex:1, display:'flex', overflow:'hidden' }}>

        {/* TABLE */}
        <div style={{ flex:1, overflow:'auto' }}>
          <table style={{ width:'100%', borderCollapse:'collapse', fontSize:12 }}>
            <thead>
              <tr style={{ background:'var(--inset)', borderBottom:'1px solid #111', position:'sticky', top:0 }}>
                {['Type','Host','Port','Username','Secret','Source','Agent','Captured','Verified','Actions'].map(h=>(
                  <th key={h} style={{ padding:'6px 12px', color:'var(--tx1)', fontWeight:400, textAlign:'left', fontSize:9, textTransform:'uppercase', borderRight:'1px solid #0d0d0d', whiteSpace:'nowrap' }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {creds.map(c => (
                <tr key={c.id} style={{ borderBottom:'1px solid #0a0a0a', cursor:'pointer' }}
                  onMouseEnter={e=>(e.currentTarget.style.background='#0d0d0d')}
                  onMouseLeave={e=>(e.currentTarget.style.background='transparent')}
                  onClick={()=>{ setSelCred(c); setShowSecret(false); }}>
                  <td style={{ padding:'7px 12px', borderRight:'1px solid #0a0a0a' }}>
                    <span style={{ fontSize:9, padding:'2px 7px', border:`1px solid ${TYPE_COL[c.type]}44`, color:TYPE_COL[c.type], background:`${TYPE_COL[c.type]}11` }}>{c.type}</span>
                  </td>
                  <td style={{ padding:'7px 12px', color:'#5bb8d4', borderRight:'1px solid #0a0a0a', fontWeight:700 }}>{c.host}</td>
                  <td style={{ padding:'7px 12px', color:'var(--tx1)', borderRight:'1px solid #0a0a0a' }}>{c.port||'—'}</td>
                  <td style={{ padding:'7px 12px', color:'#aaaaaa', borderRight:'1px solid #0a0a0a', fontWeight:700 }}>{c.username}</td>
                  <td style={{ padding:'7px 12px', color:'var(--tx2)', borderRight:'1px solid #0a0a0a', maxWidth:200, overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap' }}>
                    {'•'.repeat(Math.min(c.secret.length, 20))}
                  </td>
                  <td style={{ padding:'7px 12px', color:'var(--tx1)', borderRight:'1px solid #0a0a0a', maxWidth:180, overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap' }}>{c.source}</td>
                  <td style={{ padding:'7px 12px', color:'#e05c6e', borderRight:'1px solid #0a0a0a' }}>{c.agentId}</td>
                  <td style={{ padding:'7px 12px', color:'var(--tx2)', borderRight:'1px solid #0a0a0a', fontSize:10, whiteSpace:'nowrap' }}>{c.captured.slice(11)}</td>
                  <td style={{ padding:'7px 12px', borderRight:'1px solid #0a0a0a', textAlign:'center' }}>
                    <span style={{ color:c.verified?'#33a84a':'#d48b55' }}>{c.verified?'✓':'?'}</span>
                  </td>
                  <td style={{ padding:'7px 12px' }}>
                    <div style={{ display:'flex', gap:4 }}>
                      <button onClick={e=>{e.stopPropagation();setSelCred(c);setShowSecret(true);}} style={{ background:'transparent', border:'1px solid #1a1a1a', color:'var(--tx1)', fontFamily:'Courier New', fontSize:9, padding:'2px 6px', cursor:'pointer' }}>View</button>
                      <button onClick={e=>e.stopPropagation()} style={{ background:'transparent', border:'1px solid #1a3520', color:'#33a84a', fontFamily:'Courier New', fontSize:9, padding:'2px 6px', cursor:'pointer' }}>Use</button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {/* DETAIL PANEL */}
        {selCred && (
          <div style={{ width:320, background:'var(--inset2)', borderLeft:'1px solid #111', display:'flex', flexDirection:'column', overflow:'hidden', flexShrink:0 }}>
            <div style={{ padding:'5px 12px', background:'var(--inset)', borderBottom:'1px solid #0d0d0d', display:'flex', justifyContent:'space-between', alignItems:'center' }}>
              <span style={{ fontSize:10, color:'var(--tx1)', textTransform:'uppercase', letterSpacing:1 }}>Credential Detail</span>
              <button onClick={()=>setSelCred(null)} style={{ background:'transparent', border:'1px solid #1a1a1a', color:'var(--tx2)', fontFamily:'Courier New', fontSize:9, padding:'2px 7px', cursor:'pointer' }}>✕</button>
            </div>
            <div style={{ flex:1, overflowY:'auto', padding:'14px' }}>
              <div style={{ marginBottom:16 }}>
                <span style={{ fontSize:10, padding:'3px 10px', border:`1px solid ${TYPE_COL[selCred.type]}`, color:TYPE_COL[selCred.type], background:`${TYPE_COL[selCred.type]}11` }}>{selCred.type}</span>
                {selCred.verified && <span style={{ marginLeft:8, fontSize:10, padding:'3px 8px', border:'1px solid #33a84a', color:'#33a84a', background:'#0a1a0a' }}>VERIFIED</span>}
              </div>

              {[
                ['Host', selCred.host+':'+selCred.port],
                ['Username', selCred.username],
                ['Source', selCred.source],
                ['Agent', selCred.agentId],
                ['Captured', selCred.captured],
              ].map(([k,v])=>(
                <div key={k} style={{ marginBottom:8, padding:'6px 0', borderBottom:'1px solid #0d0d0d' }}>
                  <div style={{ fontSize:8, color:'var(--tx2)', textTransform:'uppercase', letterSpacing:1, marginBottom:3 }}>{k}</div>
                  <div style={{ fontSize:11, color: k==='Agent'?'#e05c6e':k==='Host'?'#5bb8d4':'#aaaaaa' }}>{v}</div>
                </div>
              ))}

              <div style={{ marginBottom:8, padding:'6px 0', borderBottom:'1px solid #0d0d0d' }}>
                <div style={{ fontSize:8, color:'var(--tx2)', textTransform:'uppercase', letterSpacing:1, marginBottom:3 }}>Secret</div>
                {showSecret ? (
                  <div style={{ fontSize:10, color:'#e05c6e', fontFamily:'Courier New', background:'var(--inset2)', padding:'8px', border:'1px solid #1a0000', wordBreak:'break-all', maxHeight:120, overflowY:'auto' }}>
                    {selCred.secret}
                  </div>
                ) : (
                  <button onClick={()=>setShowSecret(true)} style={{ background:'#1a0000', border:'1px solid #e05c6e', color:'#e05c6e', fontFamily:'Courier New', fontSize:10, padding:'5px 12px', cursor:'pointer' }}>
                    ⚠ Reveal Secret
                  </button>
                )}
              </div>

              {selCred.notes && (
                <div style={{ marginBottom:16 }}>
                  <div style={{ fontSize:8, color:'var(--tx2)', textTransform:'uppercase', letterSpacing:1, marginBottom:5 }}>Notes</div>
                  <div style={{ fontSize:11, color:'#777', fontStyle:'italic' }}>{selCred.notes}</div>
                </div>
              )}

              <div style={{ display:'flex', flexDirection:'column', gap:6 }}>
                <button style={{ background:'#1a0000', border:'1px solid #e05c6e', color:'#e05c6e', fontFamily:'Courier New', fontSize:11, padding:'7px', cursor:'pointer' }}>Use for SSH</button>
                <button style={{ background:'#0a1a0a', border:'1px solid #33a84a', color:'#33a84a', fontFamily:'Courier New', fontSize:11, padding:'7px', cursor:'pointer' }}>Mark Verified</button>
                <button style={{ background:'transparent', border:'1px solid #1a1a1a', color:'var(--tx1)', fontFamily:'Courier New', fontSize:11, padding:'7px', cursor:'pointer' }}>Copy to Clipboard</button>
                <button style={{ background:'transparent', border:'1px solid #1a1a1a', color:'var(--tx2)', fontFamily:'Courier New', fontSize:11, padding:'7px', cursor:'pointer' }}>Delete</button>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* STATUS */}
      <div style={{ padding:'3px 12px', background:'var(--inset2)', borderTop:'1px solid #0d0d0d', flexShrink:0, display:'flex', gap:20, fontSize:10 }}>
        <span style={{ color:'#33a84a' }}>{creds.filter(c=>c.verified).length} verified</span>
        <span style={{ color:'#d48b55' }}>{creds.filter(c=>!c.verified).length} unverified</span>
        <span style={{ marginLeft:'auto', color:'var(--tx2)' }}>Wire: GET /api/credentials — POST /api/credentials/import</span>
      </div>
    </div>
  );
}
