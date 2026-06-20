import { useState } from 'react';
import { FeedEvent } from '@/lib/models/agents/agentModel';

const TYPE_COLOR: Record<string, string> = { ok:'var(--green)', err:'var(--red-hi)', warn:'var(--orange)', sys:'var(--tx2)' };
const TYPE_ICO:   Record<string, string> = { ok:'[+]', err:'[-]', warn:'[!]', sys:'[*]' };

export default function TimelineView({ events }: { events: FeedEvent[] }) {
  const [filter, setFilter] = useState<'all'|'ok'|'err'|'warn'|'sys'>('all');
  const [search, setSearch] = useState('');

  const visible = events
    .filter(e => filter === 'all' || e.type === filter)
    .filter(e => !search || e.msg.toLowerCase().includes(search.toLowerCase()));

  return (
    <div style={{ display:'flex', flexDirection:'column', height:'100%', overflow:'hidden' }}>
      <div className="sec-hdr">
        <span style={{ color:'var(--tx2)' }}>Timeline — <span style={{ color:'var(--tx1)' }}>{events.length}</span> events</span>
        <div style={{ display:'flex', gap:4, alignItems:'center' }}>
          {(['all','ok','err','warn','sys'] as const).map(f => (
            <button key={f} className={`zk-btn${filter===f?' active':''}`} style={{ padding:'2px 8px', fontSize:10 }} onClick={()=>setFilter(f)}>
              {f.toUpperCase()}
            </button>
          ))}
          <input className="zk-input" style={{ width:160, height:20 }} placeholder="Search..." value={search} onChange={e=>setSearch(e.target.value)} />
          <button className="zk-btn" style={{ padding:'2px 8px', fontSize:10 }} onClick={()=>setSearch('')}>Clear</button>
        </div>
      </div>

      <div style={{ flex:1, overflowY:'auto' }}>
        {!visible.length && (
          <div style={{ padding:'24px 16px', color:'var(--tx3)', fontSize:11, textAlign:'center' }}>
            {!events.length ? '[*] No events — waiting for agent connections.' : `[*] No results for filter "${filter}" / "${search}"`}
          </div>
        )}

        {visible.map((ev, i) => (
          <div key={i} style={{
            display:'flex', gap:0, padding:'5px 12px',
            borderBottom:'1px solid var(--b1)', fontSize:11,
            alignItems:'baseline',
          }}
            onMouseEnter={e=>(e.currentTarget.style.background='var(--panel2)')}
            onMouseLeave={e=>(e.currentTarget.style.background='transparent')}
          >
            <span style={{ fontSize:10, color:'var(--tx3)', minWidth:64, fontFamily:'Courier New', flexShrink:0 }}>{ev.time}</span>
            <span style={{ minWidth:30, color:TYPE_COLOR[ev.type], fontFamily:'Courier New', flexShrink:0 }}>{TYPE_ICO[ev.type]}</span>
            <span style={{ color:'var(--tx1)', flex:1, overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap' }}>{ev.msg}</span>
            <span style={{ fontSize:9, color:'var(--tx3)', flexShrink:0, borderLeft:'1px solid var(--b1)', marginLeft:10, paddingLeft:10 }}>
              {ev.type.toUpperCase()}
            </span>
          </div>
        ))}
      </div>

      <div style={{ padding:'4px 12px', borderTop:'1px solid var(--b1)', background:'var(--panel)', display:'flex', gap:16, fontSize:10, color:'var(--tx3)', flexShrink:0 }}>
        {['ok','err','warn','sys'].map(t => (
          <span key={t}><span style={{ color:TYPE_COLOR[t] }}>{events.filter(e=>e.type===t).length}</span> {t}</span>
        ))}
        <span style={{ marginLeft:'auto' }}>{visible.length} / {events.length} shown</span>
      </div>
    </div>
  );
}
