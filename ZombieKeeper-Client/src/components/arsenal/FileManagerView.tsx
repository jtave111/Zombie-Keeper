import { useState } from 'react';

interface FsEntry { name:string; type:'dir'|'file'|'link'; size:string; perms:string; owner:string; modified:string; }

const MOCK_FS: Record<string, FsEntry[]> = {
  '/': [
    {name:'etc',   type:'dir',  size:'—',      perms:'drwxr-xr-x', owner:'root', modified:'2026-01-10'},
    {name:'home',  type:'dir',  size:'—',      perms:'drwxr-xr-x', owner:'root', modified:'2026-02-01'},
    {name:'var',   type:'dir',  size:'—',      perms:'drwxr-xr-x', owner:'root', modified:'2026-03-05'},
    {name:'tmp',   type:'dir',  size:'—',      perms:'drwxrwxrwt', owner:'root', modified:'2026-06-08'},
    {name:'proc',  type:'dir',  size:'—',      perms:'dr-xr-xr-x', owner:'root', modified:'2026-06-08'},
    {name:'root',  type:'dir',  size:'—',      perms:'drwx------', owner:'root', modified:'2026-06-07'},
  ],
  '/etc': [
    {name:'passwd', type:'file', size:'2.1 KB', perms:'-rw-r--r--', owner:'root', modified:'2026-05-12'},
    {name:'shadow', type:'file', size:'1.4 KB', perms:'-rw-r-----', owner:'root', modified:'2026-05-12'},
    {name:'hosts',  type:'file', size:'312 B',  perms:'-rw-r--r--', owner:'root', modified:'2026-01-03'},
    {name:'crontab',type:'file', size:'722 B',  perms:'-rw-r--r--', owner:'root', modified:'2026-03-20'},
    {name:'ssh',    type:'dir',  size:'—',      perms:'drwxr-xr-x', owner:'root', modified:'2026-01-15'},
  ],
  '/root': [
    {name:'.bash_history', type:'file', size:'8.4 KB', perms:'-rw-------', owner:'root', modified:'2026-06-08'},
    {name:'.ssh',          type:'dir',  size:'—',      perms:'drwx------', owner:'root', modified:'2026-05-30'},
    {name:'loot',          type:'dir',  size:'—',      perms:'drwx------', owner:'root', modified:'2026-06-07'},
  ],
};

const AGENTS = ['ZK-001 · WIN-DC01','ZK-002 · UBUNTU-WEB','ZK-005 · WIN-EXCH01'];
const ICON: Record<string,string> = { dir:'/', file:'f', link:'~' };
const COL:  Record<string,string> = { dir:'#5a96d4', file:'#aaaaaa', link:'#c8a84b' };

export default function FileManagerView() {
  const [agent,    setAgent]    = useState(AGENTS[0]);
  const [path,     setPath]     = useState('/');
  const [selected, setSelected] = useState<FsEntry|null>(null);
  const [uploads,  setUploads]  = useState<{name:string;prog:number}[]>([]);

  const entries = MOCK_FS[path] ?? [];

  const navigate = (e: FsEntry) => {
    if (e.type === 'dir') {
      setPath(path === '/' ? `/${e.name}` : `${path}/${e.name}`);
      setSelected(null);
    } else {
      setSelected(e);
    }
  };

  const up = () => {
    const parts = path.split('/').filter(Boolean);
    parts.pop();
    setPath(parts.length === 0 ? '/' : '/' + parts.join('/'));
    setSelected(null);
  };

  const fakeUpload = (name: string) => {
    setUploads(p => [...p, { name, prog: 0 }]);
    let v = 0;
    const iv = setInterval(() => {
      v += Math.floor(10 + Math.random() * 20);
      if (v >= 100) { v = 100; clearInterval(iv); }
      setUploads(p => p.map(u => u.name===name ? {...u,prog:v} : u));
    }, 120);
  };

  const breadcrumb = ['root', ...path.split('/').filter(Boolean)];

  return (
    <div style={{ display:'flex', height:'100%', overflow:'hidden', fontFamily:'Courier New' }}>

      {/* LEFT — agent + actions */}
      <div style={{ width:210, background:'var(--inset2)', borderRight:'1px solid #1a1a1a', display:'flex', flexDirection:'column', flexShrink:0 }}>
        <div style={{ padding:'8px 10px', borderBottom:'1px solid #1a1a1a', fontSize:9, color:'var(--tx2)', textTransform:'uppercase', letterSpacing:1 }}>Agent</div>
        <div style={{ padding:'8px 10px', borderBottom:'1px solid #1a1a1a' }}>
          <select value={agent} onChange={e=>setAgent(e.target.value)}
            style={{ width:'100%', background:'var(--inset2)', border:'1px solid #1e1e1e', color:'#ccc', fontFamily:'Courier New', fontSize:11, padding:'4px 8px', outline:'none', appearance:'none' }}>
            {AGENTS.map(a=><option key={a}>{a}</option>)}
          </select>
        </div>

        {/* Quick actions */}
        <div style={{ padding:'8px 10px', borderBottom:'1px solid #1a1a1a' }}>
          <div style={{ fontSize:9, color:'var(--tx2)', textTransform:'uppercase', letterSpacing:1, marginBottom:6 }}>Quick Paths</div>
          {['/', '/etc', '/root', '/home', '/var', '/tmp'].map(p => (
            <div key={p} onClick={()=>{setPath(p);setSelected(null);}} style={{
              padding:'3px 8px', fontSize:11, cursor:'pointer', marginBottom:2,
              color: path===p ? '#e05c6e' : '#444',
              background: path===p ? '#1a0000' : 'transparent',
            }}>{p}</div>
          ))}
        </div>

        {/* Upload zone */}
        <div style={{ padding:'8px 10px', borderBottom:'1px solid #1a1a1a' }}>
          <div style={{ fontSize:9, color:'var(--tx2)', textTransform:'uppercase', letterSpacing:1, marginBottom:6 }}>Upload to {path}</div>
          <div
            onDrop={e=>{e.preventDefault();[...e.dataTransfer.files].forEach(f=>fakeUpload(f.name));}}
            onDragOver={e=>e.preventDefault()}
            style={{ border:'1px dashed #1a1a1a', padding:'10px 8px', textAlign:'center', fontSize:10, color:'var(--tx2)', cursor:'pointer' }}
            onClick={()=>fakeUpload(`payload_${Date.now()}.elf`)}>
            drop file / click
          </div>
          {uploads.map(u=>(
            <div key={u.name} style={{ marginTop:4 }}>
              <div style={{ fontSize:9, color:'var(--tx1)', marginBottom:2, overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap' }}>{u.name}</div>
              <div style={{ height:3, background:'var(--inset)', borderRadius:2 }}>
                <div style={{ height:'100%', width:`${u.prog}%`, background: u.prog===100?'#33a84a':'#d48b55', borderRadius:2, transition:'width 0.1s' }}/>
              </div>
            </div>
          ))}
        </div>

        <div style={{ flex:1 }}/>

        {/* Selected file actions */}
        {selected && (
          <div style={{ padding:'8px 10px', borderTop:'1px solid #1a1a1a' }}>
            <div style={{ fontSize:9, color:'var(--tx1)', marginBottom:6 }}>{selected.name}</div>
            {[['Download','#e05c6e'],['View','#777'],['Execute','#d48b55'],['Delete','#e05c6e']].map(([l,c])=>(
              <button key={l} style={{ width:'100%', background:'var(--inset2)', border:`1px solid ${l==='Delete'?'#3a1220':'#1a1a1a'}`, color:c as string, fontFamily:'Courier New', fontSize:10, padding:'4px', cursor:'pointer', marginBottom:3 }}>{l}</button>
            ))}
          </div>
        )}
      </div>

      {/* RIGHT — file listing */}
      <div style={{ flex:1, display:'flex', flexDirection:'column', overflow:'hidden' }}>
        {/* Breadcrumb + toolbar */}
        <div style={{ padding:'6px 14px', background:'var(--inset2)', borderBottom:'1px solid #1a1a1a', display:'flex', alignItems:'center', gap:8, flexShrink:0 }}>
          {path !== '/' && (
            <button onClick={up} style={{ background:'var(--inset2)', border:'1px solid #1a1a1a', color:'var(--tx2)', fontFamily:'Courier New', fontSize:10, padding:'2px 8px', cursor:'pointer' }}>↑ up</button>
          )}
          <div style={{ display:'flex', gap:4, fontSize:11 }}>
            {breadcrumb.map((seg,i)=>(
              <span key={i} style={{ color: i===breadcrumb.length-1?'#cccccc':'#333' }}>
                {i>0&&<span style={{color:'var(--tx3)',margin:'0 2px'}}>/</span>}{seg}
              </span>
            ))}
          </div>
          <span style={{ marginLeft:'auto', fontSize:10, color:'var(--tx2)' }}>{entries.length} entries</span>
        </div>

        {/* Table header */}
        <div style={{ display:'grid', gridTemplateColumns:'28px 1fr 80px 120px 80px 90px', padding:'4px 14px', background:'var(--inset)', borderBottom:'1px solid #1a1a1a', fontSize:9, color:'var(--tx2)', textTransform:'uppercase', letterSpacing:0.8, flexShrink:0 }}>
          <span/><span>Name</span><span style={{textAlign:'right'}}>Size</span><span>Permissions</span><span>Owner</span><span>Modified</span>
        </div>

        {/* Entries */}
        <div style={{ flex:1, overflowY:'auto' }}>
          {entries.length === 0 && (
            <div style={{ padding:'20px 14px', color:'var(--tx3)', fontSize:11 }}>[*] Empty directory or path not cached — TODO: fetch via agent</div>
          )}
          {entries.map(e => (
            <div key={e.name}
              onClick={()=>navigate(e)}
              style={{
                display:'grid', gridTemplateColumns:'28px 1fr 80px 120px 80px 90px',
                padding:'5px 14px', borderBottom:'1px solid #0d0d0d', cursor:'pointer',
                background: selected?.name===e.name ? '#0d0d14' : 'transparent',
              }}
              onMouseEnter={el=>(el.currentTarget.style.background='#0a0a0a')}
              onMouseLeave={el=>(el.currentTarget.style.background=selected?.name===e.name?'#0d0d14':'transparent')}>
              <span style={{ fontSize:10, color:COL[e.type], fontWeight:700 }}>{ICON[e.type]}</span>
              <span style={{ fontSize:11, color:COL[e.type] }}>{e.name}</span>
              <span style={{ fontSize:10, color:'var(--tx2)', textAlign:'right' }}>{e.size}</span>
              <span style={{ fontSize:10, color:'var(--tx2)', fontFamily:'monospace' }}>{e.perms}</span>
              <span style={{ fontSize:10, color:'var(--tx2)' }}>{e.owner}</span>
              <span style={{ fontSize:10, color:'var(--tx2)' }}>{e.modified}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
