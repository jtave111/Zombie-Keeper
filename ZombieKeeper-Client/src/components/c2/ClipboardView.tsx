import { useState } from 'react';

interface Clip { id: number; label: string; text: string; ts: string; tag: string; }

const TAG_COLORS: Record<string, string> = {
  cred:'var(--red)',  hash:'var(--orange)', ip:'var(--cyan)',
  cmd:'var(--yellow)', note:'var(--tx2)',   other:'var(--tx3)',
};

export default function ClipboardView() {
  const [items,  setItems]  = useState<Clip[]>([]);
  const [text,   setText]   = useState('');
  const [label,  setLabel]  = useState('');
  const [tag,    setTag]    = useState('other');
  const [search, setSearch] = useState('');
  const [copied, setCopied] = useState<number|null>(null);

  const add = () => {
    if (!text.trim()) return;
    const now = new Date();
    const ts  = `${now.getUTCHours().toString().padStart(2,'0')}:${now.getUTCMinutes().toString().padStart(2,'0')} UTC`;
    setItems(prev => [{ id:Date.now(), label:label.trim()||'Untitled', text:text.trim(), ts, tag }, ...prev]);
    setText(''); setLabel('');
  };

  const copy = (item: Clip) => {
    navigator.clipboard.writeText(item.text).catch(()=>{});
    setCopied(item.id);
    setTimeout(()=>setCopied(null), 1500);
  };

  const paste = () =>
    navigator.clipboard.readText().then(t => setText(t)).catch(()=>{});

  const visible = items.filter(i =>
    !search || i.label.toLowerCase().includes(search.toLowerCase()) || i.text.toLowerCase().includes(search.toLowerCase())
  );

  return (
    <div style={{ display:'flex', height:'100%', overflow:'hidden' }}>

      {/* Input panel */}
      <div style={{ width:280, flexShrink:0, borderRight:'1px solid var(--b1)', display:'flex', flexDirection:'column', background:'var(--inset2)', overflow:'hidden' }}>
        <div className="sec-hdr">Add Entry</div>
        <div style={{ padding:'10px 10px', display:'flex', flexDirection:'column', gap:8, flex:1 }}>
          <div style={{ display:'flex', flexDirection:'column', gap:3 }}>
            <label style={{ fontSize:10, color:'var(--tx3)', textTransform:'uppercase', letterSpacing:0.5 }}>Label</label>
            <input className="zk-input" value={label} onChange={e=>setLabel(e.target.value)} placeholder="NTLM hash, cred, IP..." />
          </div>
          <div style={{ display:'flex', flexDirection:'column', gap:3 }}>
            <label style={{ fontSize:10, color:'var(--tx3)', textTransform:'uppercase', letterSpacing:0.5 }}>Tag</label>
            <select className="zk-select" value={tag} onChange={e=>setTag(e.target.value)}>
              <option value="cred">CRED</option>
              <option value="hash">HASH</option>
              <option value="ip">IP/HOST</option>
              <option value="cmd">COMMAND</option>
              <option value="note">NOTE</option>
              <option value="other">OTHER</option>
            </select>
          </div>
          <div style={{ display:'flex', flexDirection:'column', gap:3, flex:1 }}>
            <div style={{ display:'flex', justifyContent:'space-between', alignItems:'center' }}>
              <label style={{ fontSize:10, color:'var(--tx3)', textTransform:'uppercase', letterSpacing:0.5 }}>Content</label>
              <button className="zk-btn" style={{ fontSize:9, padding:'1px 6px' }} onClick={paste}>Paste</button>
            </div>
            <textarea
              className="zk-input"
              style={{ flex:1, resize:'none', fontFamily:'Courier New', fontSize:11, minHeight:120 }}
              value={text}
              onChange={e=>setText(e.target.value)}
              placeholder="Paste credentials, hashes, IPs, commands..."
              onKeyDown={e=>{ if ((e.ctrlKey||e.metaKey) && e.key==='Enter') add(); }}
            />
          </div>
        </div>
        <div style={{ padding:'8px 10px', borderTop:'1px solid var(--b1)', flexShrink:0 }}>
          <button className="zk-btn primary" style={{ width:'100%' }} onClick={add}>⊕ Add (Ctrl+Enter)</button>
        </div>
      </div>

      {/* List */}
      <div style={{ flex:1, display:'flex', flexDirection:'column', overflow:'hidden' }}>
        <div className="sec-hdr">
          <span style={{ color:'var(--tx2)' }}>Clipboard — <span style={{ color:'var(--tx1)' }}>{items.length}</span> items</span>
          <input className="zk-input" style={{ width:200, height:20 }} placeholder="Search..." value={search} onChange={e=>setSearch(e.target.value)} />
        </div>

        <div style={{ flex:1, overflowY:'auto' }}>
          {!items.length && (
            <div style={{ padding:'24px 16px', color:'var(--tx3)', fontSize:11 }}>
              [*] Empty clipboard — add credentials, hashes, IPs, or commands from targets.
            </div>
          )}
          {!visible.length && items.length > 0 && (
            <div style={{ padding:'12px 16px', color:'var(--tx3)', fontSize:11 }}>[*] No results for "{search}"</div>
          )}
          {visible.map(item => (
            <div key={item.id} style={{ borderBottom:'1px solid var(--b1)' }}
              onMouseEnter={e=>(e.currentTarget.style.background='var(--panel2)')}
              onMouseLeave={e=>(e.currentTarget.style.background='transparent')}>
              <div style={{ display:'flex', alignItems:'center', gap:8, padding:'6px 12px 3px' }}>
                <span style={{ fontSize:9, padding:'1px 5px', border:`1px solid ${TAG_COLORS[item.tag]}`, color:TAG_COLORS[item.tag], fontFamily:'Courier New', flexShrink:0 }}>
                  {item.tag.toUpperCase()}
                </span>
                <span style={{ fontSize:12, color:'var(--tx0)', fontWeight:600, flex:1, overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap' }}>{item.label}</span>
                <span style={{ fontSize:10, color:'var(--tx3)', flexShrink:0 }}>{item.ts}</span>
                <button
                  className={`zk-btn${copied===item.id?' active':''}`}
                  style={{ padding:'1px 8px', fontSize:10, flexShrink:0 }}
                  onClick={()=>copy(item)}
                >{copied===item.id?'✓ Copied':'Copy'}</button>
                <button
                  className="zk-btn danger"
                  style={{ padding:'1px 6px', fontSize:11, flexShrink:0 }}
                  onClick={()=>setItems(prev=>prev.filter(i=>i.id!==item.id))}
                >×</button>
              </div>
              <pre style={{ fontSize:11, color:'var(--tx2)', fontFamily:'Courier New', padding:'2px 12px 6px 12px', margin:0, whiteSpace:'pre-wrap', wordBreak:'break-all', maxHeight:52, overflow:'hidden' }}>
                {item.text.length>220 ? item.text.slice(0,220)+'…' : item.text}
              </pre>
            </div>
          ))}
        </div>

        {/* Tag summary bar */}
        <div style={{ padding:'4px 12px', borderTop:'1px solid var(--b1)', background:'var(--panel)', display:'flex', gap:14, fontSize:10, flexShrink:0 }}>
          {Object.entries(TAG_COLORS).map(([t, c]) => (
            <span key={t}><span style={{ color:c }}>{items.filter(i=>i.tag===t).length}</span> {t}</span>
          ))}
        </div>
      </div>
    </div>
  );
}
