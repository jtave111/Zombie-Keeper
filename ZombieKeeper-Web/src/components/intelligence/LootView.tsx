import { useState } from 'react';

interface LootFile {
  id: number;
  name: string;
  path: string;
  size: string;
  type: 'Config' | 'Key/Cert' | 'Database' | 'Screenshot' | 'Log' | 'Document' | 'Hash File' | 'Other';
  host: string;
  agentId: string;
  captured: string;
  sha256: string;
  notes: string;
  tags: string[];
}

const MOCK_LOOT: LootFile[] = [];

const TYPE_COL: Record<string,string> = {
  'Config':'#5bb8d4','Key/Cert':'#33a84a','Database':'#c8a84b',
  'Screenshot':'#a07fd4','Log':'#d48b55','Document':'#e8e8e8',
  'Hash File':'#e05c6e','Other':'#555',
};

export default function LootView() {
  const [search,  setSearch]  = useState('');
  const [filter,  setFilter]  = useState('ALL');
  const [selItem, setSelItem] = useState<LootFile | null>(null);
  const [tag,     setTag]     = useState('');

  const types = ['ALL', ...Array.from(new Set(MOCK_LOOT.map(l=>l.type)))];
  const loot  = MOCK_LOOT.filter(l => {
    const mf = filter==='ALL' || l.type===filter;
    const mt = !tag || l.tags.includes(tag);
    const ms = !search || [l.name,l.host,l.path,l.notes,l.agentId].some(v=>v.toLowerCase().includes(search.toLowerCase()));
    return mf && ms && mt;
  });
  const allTags = Array.from(new Set(MOCK_LOOT.flatMap(l=>l.tags))).sort();
  const totalSize = '18.4 MB';

  return (
    <div style={{ display:'flex', flexDirection:'column', height:'100%', overflow:'hidden', background:'#080808', fontFamily:'Courier New' }}>

      {/* STAT BAR */}
      <div style={{ display:'flex', gap:0, flexShrink:0, borderBottom:'1px solid #111' }}>
        {[
          { l:'Total Files',    v:String(MOCK_LOOT.length), c:'#e8e8e8' },
          { l:'Total Size',     v:totalSize,                c:'#5bb8d4' },
          { l:'Critical',       v:String(MOCK_LOOT.filter(l=>l.tags.includes('critical')).length), c:'#e05c6e' },
          { l:'Screenshots',    v:String(MOCK_LOOT.filter(l=>l.type==='Screenshot').length), c:'#a07fd4' },
          { l:'Keys / Certs',   v:String(MOCK_LOOT.filter(l=>l.type==='Key/Cert').length), c:'#33a84a' },
          { l:'Hash Files',     v:String(MOCK_LOOT.filter(l=>l.type==='Hash File').length), c:'#e05c6e' },
          { l:'Agents',         v:String(new Set(MOCK_LOOT.map(l=>l.agentId)).size), c:'#d48b55' },
        ].map((s,i)=>(
          <div key={i} style={{ flex:1, padding:'10px 14px', borderRight:'1px solid #111', background:'#0d0d0d' }}>
            <div style={{ fontSize:9, color:'#555', textTransform:'uppercase', letterSpacing:'1px', marginBottom:5 }}>{s.l}</div>
            <div style={{ fontSize:20, fontWeight:700, color:s.c }}>{s.v}</div>
          </div>
        ))}
      </div>

      {/* TOOLBAR */}
      <div style={{ display:'flex', alignItems:'center', gap:8, padding:'6px 12px', background:'#0d0d0d', borderBottom:'1px solid #111', flexShrink:0, flexWrap:'wrap' }}>
        <input value={search} onChange={e=>setSearch(e.target.value)} placeholder="search name, host, notes..."
          style={{ width:240, background:'#080808', border:'1px solid #1a1a1a', color:'#e8e8e8', fontFamily:'Courier New', fontSize:12, padding:'5px 8px', outline:'none' }}/>
        <span style={{ color:'#1a1a1a' }}>|</span>
        {types.map(t=>(
          <button key={t} onClick={()=>setFilter(t)} style={{
            background:filter===t?'#1a0000':'transparent', border:`1px solid ${filter===t?'#e05c6e':'#111'}`,
            color:filter===t?'#e05c6e':'#555', fontFamily:'Courier New', fontSize:10,
            padding:'4px 10px', cursor:'pointer', textTransform:'uppercase',
          }}>{t}</button>
        ))}
        <span style={{ color:'#1a1a1a' }}>|</span>
        <select value={tag} onChange={e=>setTag(e.target.value)} style={{ background:'#0d0d0d', border:'1px solid #111', color:'#555', fontFamily:'Courier New', fontSize:11, padding:'4px 8px', outline:'none' }}>
          <option value="">All Tags</option>
          {allTags.map(t=><option key={t}>{t}</option>)}
        </select>
        <div style={{ marginLeft:'auto', display:'flex', gap:6 }}>
          <button style={{ background:'transparent', border:'1px solid #111', color:'#777', fontFamily:'Courier New', fontSize:10, padding:'4px 10px', cursor:'pointer' }}>Export All</button>
          <button style={{ background:'transparent', border:'1px solid #111', color:'#777', fontFamily:'Courier New', fontSize:10, padding:'4px 10px', cursor:'pointer' }}>Download ZIP</button>
        </div>
      </div>

      <div style={{ flex:1, display:'flex', overflow:'hidden' }}>
        {/* TABLE */}
        <div style={{ flex:1, overflow:'auto' }}>
          <table style={{ width:'100%', borderCollapse:'collapse', fontSize:12 }}>
            <thead>
              <tr style={{ background:'#111', borderBottom:'1px solid #111', position:'sticky', top:0 }}>
                {['Type','Filename','Path','Size','Host','Agent','Captured','Tags','Actions'].map(h=>(
                  <th key={h} style={{ padding:'6px 12px', color:'#555', fontWeight:400, textAlign:'left', fontSize:9, textTransform:'uppercase', borderRight:'1px solid #0d0d0d', whiteSpace:'nowrap' }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {loot.map(l=>(
                <tr key={l.id} style={{ borderBottom:'1px solid #0a0a0a', cursor:'pointer' }}
                  onMouseEnter={e=>(e.currentTarget.style.background='#0d0d0d')}
                  onMouseLeave={e=>(e.currentTarget.style.background='transparent')}
                  onClick={()=>setSelItem(l)}>
                  <td style={{ padding:'7px 12px', borderRight:'1px solid #0a0a0a' }}>
                    <span style={{ fontSize:9, padding:'2px 7px', border:`1px solid ${TYPE_COL[l.type]}44`, color:TYPE_COL[l.type], background:`${TYPE_COL[l.type]}11` }}>{l.type}</span>
                  </td>
                  <td style={{ padding:'7px 12px', color:'#aaaaaa', borderRight:'1px solid #0a0a0a', fontWeight:700 }}>{l.name}</td>
                  <td style={{ padding:'7px 12px', color:'#555', borderRight:'1px solid #0a0a0a', fontSize:10, maxWidth:220, overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap' }}>{l.path}</td>
                  <td style={{ padding:'7px 12px', color:'#777', borderRight:'1px solid #0a0a0a', whiteSpace:'nowrap' }}>{l.size}</td>
                  <td style={{ padding:'7px 12px', color:'#5bb8d4', borderRight:'1px solid #0a0a0a' }}>{l.host}</td>
                  <td style={{ padding:'7px 12px', color:'#e05c6e', borderRight:'1px solid #0a0a0a' }}>{l.agentId}</td>
                  <td style={{ padding:'7px 12px', color:'#444', borderRight:'1px solid #0a0a0a', fontSize:10, whiteSpace:'nowrap' }}>{l.captured.slice(11)}</td>
                  <td style={{ padding:'7px 12px', borderRight:'1px solid #0a0a0a' }}>
                    <div style={{ display:'flex', gap:3, flexWrap:'wrap' }}>
                      {l.tags.map(t=>(
                        <span key={t} onClick={e=>{e.stopPropagation();setTag(t);}}
                          style={{ fontSize:8, padding:'1px 5px', border:`1px solid ${t==='critical'?'#e05c6e44':'#1a1a1a'}`, color:t==='critical'?'#e05c6e':'#555', cursor:'pointer' }}>{t}</span>
                      ))}
                    </div>
                  </td>
                  <td style={{ padding:'7px 12px' }}>
                    <div style={{ display:'flex', gap:4 }}>
                      <button onClick={e=>{e.stopPropagation();setSelItem(l);}} style={{ background:'transparent', border:'1px solid #1a1a1a', color:'#555', fontFamily:'Courier New', fontSize:9, padding:'2px 6px', cursor:'pointer' }}>View</button>
                      <button onClick={e=>e.stopPropagation()} style={{ background:'transparent', border:'1px solid #1a3520', color:'#33a84a', fontFamily:'Courier New', fontSize:9, padding:'2px 6px', cursor:'pointer' }}>DL</button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {/* DETAIL PANEL */}
        {selItem && (
          <div style={{ width:300, background:'#0a0a0a', borderLeft:'1px solid #111', display:'flex', flexDirection:'column', overflow:'hidden', flexShrink:0 }}>
            <div style={{ padding:'5px 12px', background:'#111', borderBottom:'1px solid #0d0d0d', display:'flex', justifyContent:'space-between', alignItems:'center' }}>
              <span style={{ fontSize:10, color:'#555', textTransform:'uppercase', letterSpacing:1 }}>File Detail</span>
              <button onClick={()=>setSelItem(null)} style={{ background:'transparent', border:'1px solid #1a1a1a', color:'#444', fontFamily:'Courier New', fontSize:9, padding:'2px 7px', cursor:'pointer' }}>✕</button>
            </div>
            <div style={{ flex:1, overflowY:'auto', padding:'14px' }}>
              <div style={{ marginBottom:12 }}>
                <span style={{ fontSize:10, padding:'2px 8px', border:`1px solid ${TYPE_COL[selItem.type]}`, color:TYPE_COL[selItem.type] }}>{selItem.type}</span>
              </div>
              {[
                ['Name',selItem.name],['Path',selItem.path],['Size',selItem.size],
                ['Host',selItem.host],['Agent',selItem.agentId],
                ['Captured',selItem.captured],['SHA256',selItem.sha256],
              ].map(([k,v])=>(
                <div key={k} style={{ marginBottom:7, paddingBottom:6, borderBottom:'1px solid #0a0a0a' }}>
                  <div style={{ fontSize:8, color:'#333', textTransform:'uppercase', letterSpacing:1, marginBottom:2 }}>{k}</div>
                  <div style={{ fontSize:10, color:k==='Agent'?'#e05c6e':k==='Host'?'#5bb8d4':k==='SHA256'?'#333':'#aaaaaa', wordBreak:'break-all' }}>{v}</div>
                </div>
              ))}
              {selItem.notes && (
                <div style={{ marginBottom:14 }}>
                  <div style={{ fontSize:8, color:'#333', textTransform:'uppercase', letterSpacing:1, marginBottom:5 }}>Notes</div>
                  <div style={{ fontSize:11, color:'#777' }}>{selItem.notes}</div>
                </div>
              )}
              <div style={{ display:'flex', flexDirection:'column', gap:6, marginTop:10 }}>
                <button style={{ background:'#0a1a0a', border:'1px solid #33a84a', color:'#33a84a', fontFamily:'Courier New', fontSize:11, padding:'7px', cursor:'pointer' }}>Download File</button>
                <button style={{ background:'transparent', border:'1px solid #1a1a1a', color:'#555', fontFamily:'Courier New', fontSize:11, padding:'7px', cursor:'pointer' }}>Copy Path</button>
                <button style={{ background:'transparent', border:'1px solid #1a1a1a', color:'#333', fontFamily:'Courier New', fontSize:11, padding:'7px', cursor:'pointer' }}>Delete from Loot</button>
              </div>
            </div>
          </div>
        )}
      </div>

      <div style={{ padding:'3px 12px', background:'#0d0d0d', borderTop:'1px solid #0d0d0d', flexShrink:0, display:'flex', gap:20, fontSize:10 }}>
        <span style={{ color:'#e05c6e' }}>{MOCK_LOOT.filter(l=>l.tags.includes('critical')).length} critical files</span>
        <span style={{ color:'#5bb8d4' }}>{totalSize} total</span>
        <span style={{ marginLeft:'auto', color:'#333' }}>Wire: GET /api/loot — GET /api/loot/:id/download</span>
      </div>
    </div>
  );
}
