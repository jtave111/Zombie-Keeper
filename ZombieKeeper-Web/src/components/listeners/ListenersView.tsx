'use client';
import { useState } from 'react';

const MOCK_LISTENERS: { id:number; name:string; protocol:string; host:string; port:number; status:string; agents:number }[] = [];

export default function ListenersView() {
  const [sel,setSel]     = useState<number|null>(null);
  const [showNew,setNew] = useState(false);

  return (
    <div style={{ display:'flex', flexDirection:'column', height:'100%', overflow:'hidden' }}>
      <div style={{ display:'flex', alignItems:'center', padding:'6px 10px', background:'#111', borderBottom:'1px solid #222', flexShrink:0 }}>
        <span style={{ fontSize:10, color:'#444', textTransform:'uppercase', letterSpacing:1 }}>C2 Listeners</span>
        <button onClick={()=>setNew(true)} style={{ marginLeft:'auto', background:'#1a0000', border:'1px solid #e05c6e', color:'#e05c6e', fontFamily:'Courier New', fontSize:11, padding:'4px 12px', cursor:'pointer' }}>+ New Listener</button>
      </div>
      <div style={{ flex:1, overflow:'auto' }}>
        <table style={{ width:'100%', borderCollapse:'collapse', fontFamily:'Courier New', fontSize:12 }}>
          <thead>
            <tr style={{ background:'#111', borderBottom:'1px solid #222', position:'sticky', top:0 }}>
              {['ID','Name','Protocol','Host','Port','Status','Agents','Actions'].map(h=>(
                <th key={h} style={{ padding:'5px 10px', color:'#444', fontWeight:400, textAlign:'left', fontSize:10, textTransform:'uppercase', borderRight:'1px solid #111' }}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {MOCK_LISTENERS.map(l=>(
              <tr key={l.id} style={{ borderBottom:'1px solid #111', cursor:'pointer', background:sel===l.id?'#1a0000':'transparent' }}
                onClick={()=>setSel(l.id===sel?null:l.id)}
                onMouseEnter={e=>(e.currentTarget.style.background='#111')}
                onMouseLeave={e=>(e.currentTarget.style.background=sel===l.id?'#1a0000':'transparent')}>
                <td style={{ padding:'7px 10px', color:'#555', borderRight:'1px solid #111' }}>{l.id}</td>
                <td style={{ padding:'7px 10px', color:'#cccccc', borderRight:'1px solid #111' }}>{l.name}</td>
                <td style={{ padding:'7px 10px', color:'#5bb8d4', borderRight:'1px solid #111' }}>{l.protocol}</td>
                <td style={{ padding:'7px 10px', color:'#666', borderRight:'1px solid #111' }}>{l.host}</td>
                <td style={{ padding:'7px 10px', color:'#888', borderRight:'1px solid #111' }}>{l.port}</td>
                <td style={{ padding:'7px 10px', borderRight:'1px solid #111' }}>
                  <span style={{ color:l.status==='ONLINE'?'#33a84a':'#444', fontWeight:700 }}>{l.status==='ONLINE'?'[*]':'[!]'} {l.status}</span>
                </td>
                <td style={{ padding:'7px 10px', color:'#e05c6e', fontWeight:700, borderRight:'1px solid #111' }}>{l.agents}</td>
                <td style={{ padding:'7px 10px' }}>
                  <div style={{ display:'flex', gap:4 }}>
                    <button style={{ background:'transparent', border:'1px solid #2a2a2a', color:'#555', fontFamily:'Courier New', fontSize:10, padding:'2px 7px', cursor:'pointer' }}>Edit</button>
                    <button style={{ background:'transparent', border:'1px solid #e05c6e', color:'#e05c6e', fontFamily:'Courier New', fontSize:10, padding:'2px 7px', cursor:'pointer' }}>Stop</button>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {showNew && (
        <div style={{ position:'fixed', inset:0, background:'rgba(0,0,0,0.85)', display:'flex', alignItems:'center', justifyContent:'center', zIndex:100 }}>
          <div style={{ background:'#0d0d0d', border:'1px solid #e05c6e', padding:'24px', width:400, fontFamily:'Courier New' }}>
            <div style={{ fontSize:13, color:'#cccccc', fontWeight:700, marginBottom:16 }}>New Listener</div>
            {[['Name','HTTP-New'],['Host','0.0.0.0'],['Port','4444']].map(([l,ph])=>(
              <div key={l} style={{ marginBottom:12 }}>
                <div style={{ fontSize:9, color:'#444', textTransform:'uppercase', letterSpacing:1, marginBottom:4 }}>{l}</div>
                <input defaultValue={ph} style={{ width:'100%', background:'#080808', border:'1px solid #222', color:'#cccccc', fontFamily:'Courier New', fontSize:12, padding:'6px 8px', outline:'none' }}/>
              </div>
            ))}
            <div style={{ marginBottom:16 }}>
              <div style={{ fontSize:9, color:'#444', textTransform:'uppercase', letterSpacing:1, marginBottom:4 }}>Protocol</div>
              <select style={{ width:'100%', background:'#080808', border:'1px solid #222', color:'#cccccc', fontFamily:'Courier New', fontSize:12, padding:'6px 8px' }}>
                <option>HTTP</option><option>HTTPS</option><option>DNS</option>
              </select>
            </div>
            <div style={{ display:'flex', gap:8 }}>
              <button onClick={()=>setNew(false)} style={{ flex:1, background:'#1a0000', border:'1px solid #e05c6e', color:'#e05c6e', fontFamily:'Courier New', fontSize:11, padding:'8px', cursor:'pointer' }}>Create</button>
              <button onClick={()=>setNew(false)} style={{ background:'transparent', border:'1px solid #222', color:'#555', fontFamily:'Courier New', fontSize:11, padding:'8px 14px', cursor:'pointer' }}>Cancel</button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
