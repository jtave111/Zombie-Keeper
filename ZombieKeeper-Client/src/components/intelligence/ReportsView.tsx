import { useState } from 'react';

interface Report {
  id: number;
  title: string;
  type: 'Campaign Summary' | 'Vulnerability Report' | 'Credential Dump' | 'Network Recon' | 'Executive Summary' | 'Technical Detail';
  status: 'Draft' | 'Generated' | 'Exported';
  created: string;
  size: string;
  agents: number;
  vulns: number;
  creds: number;
}

const MOCK_REPORTS: Report[] = [];

const SECTIONS = [
  { key:'executive',  label:'Executive Summary',     desc:'High-level risk overview for management' },
  { key:'scope',      label:'Scope & Methodology',   desc:'Targets, timeframe, tools used' },
  { key:'agents',     label:'Agent Sessions',         desc:'All agent compromises and timelines' },
  { key:'network',    label:'Network Recon',          desc:'Discovered nodes, open ports, topology' },
  { key:'vulns',      label:'Vulnerabilities',        desc:'All CVEs and risk findings by severity' },
  { key:'creds',      label:'Credentials',            desc:'Harvested credentials by type/host' },
  { key:'loot',       label:'Collected Loot',         desc:'All downloaded files and screenshots' },
  { key:'timeline',   label:'Attack Timeline',        desc:'Chronological activity log' },
  { key:'remediation',label:'Remediation Plan',       desc:'Recommended fixes per finding' },
];

const TYPE_COL: Record<string,string> = {
  'Campaign Summary':'#e05c6e', 'Vulnerability Report':'#d48b55',
  'Credential Dump':'#5bb8d4', 'Network Recon':'#33a84a',
  'Executive Summary':'#a07fd4', 'Technical Detail':'#c8a84b',
};
const STATUS_COL: Record<string,string> = {
  Draft:'#555', Generated:'#33a84a', Exported:'#5bb8d4',
};

export default function ReportsView() {
  const [tab,     setTab]     = useState<'list'|'builder'>('list');
  const [selRep,  setSelRep]  = useState<Report | null>(null);
  const [selSecs, setSelSecs] = useState<string[]>(['executive','scope','agents','network','vulns','creds','remediation']);
  const [repTitle,setRepTitle]= useState('Penetration Test Report — Jan 2024');
  const [repType, setRepType] = useState('Campaign Summary');
  const [format,  setFormat]  = useState<'PDF'|'HTML'|'MD'|'JSON'>('PDF');
  const [building,setBuilding]= useState(false);
  const [built,   setBuilt]   = useState(false);

  const toggleSec = (k: string) =>
    setSelSecs(p => p.includes(k) ? p.filter(s=>s!==k) : [...p, k]);

  const generate = () => {
    setBuilding(true); setBuilt(false);
    setTimeout(() => { setBuilding(false); setBuilt(true); }, 2200);
  };

  return (
    <div style={{ display:'flex', flexDirection:'column', height:'100%', overflow:'hidden', background:'var(--inset2)', fontFamily:'Courier New' }}>

      {/* TABS */}
      <div style={{ display:'flex', background:'var(--inset2)', borderBottom:'1px solid #111', flexShrink:0 }}>
        {[{k:'list',l:'Report Library'},{k:'builder',l:'Report Builder'}].map(t=>(
          <button key={t.k} onClick={()=>setTab(t.k as any)} style={{
            padding:'7px 18px', background:tab===t.k?'#080808':'transparent',
            border:'none', borderTop:tab===t.k?'2px solid #e05c6e':'2px solid transparent',
            color:tab===t.k?'#e8e8e8':'#555', fontFamily:'Courier New', fontSize:11,
            cursor:'pointer', textTransform:'uppercase', letterSpacing:0.8,
          }}>{t.l}</button>
        ))}
        <div style={{ marginLeft:'auto', padding:'0 12px', display:'flex', alignItems:'center', gap:8 }}>
          <span style={{ fontSize:10, color:'var(--tx2)' }}>{MOCK_REPORTS.length} reports</span>
        </div>
      </div>

      {tab === 'list' && (
        <div style={{ flex:1, display:'flex', overflow:'hidden' }}>
          {/* REPORT LIST */}
          <div style={{ flex:1, overflow:'auto' }}>
            {/* Stat bar */}
            <div style={{ display:'flex', gap:0, borderBottom:'1px solid #111' }}>
              {[
                {l:'Total Reports',v:String(MOCK_REPORTS.length),c:'#e8e8e8'},
                {l:'Exported',v:String(MOCK_REPORTS.filter(r=>r.status==='Exported').length),c:'#5bb8d4'},
                {l:'Generated',v:String(MOCK_REPORTS.filter(r=>r.status==='Generated').length),c:'#33a84a'},
                {l:'Drafts',v:String(MOCK_REPORTS.filter(r=>r.status==='Draft').length),c:'#555'},
              ].map((s,i)=>(
                <div key={i} style={{ flex:1,padding:'10px 14px',borderRight:'1px solid #111',background:'var(--inset2)' }}>
                  <div style={{ fontSize:9,color:'var(--tx1)',textTransform:'uppercase',letterSpacing:'1px',marginBottom:5 }}>{s.l}</div>
                  <div style={{ fontSize:20,fontWeight:700,color:s.c }}>{s.v}</div>
                </div>
              ))}
            </div>

            <table style={{ width:'100%', borderCollapse:'collapse', fontSize:12 }}>
              <thead>
                <tr style={{ background:'var(--inset)', borderBottom:'1px solid #111', position:'sticky', top:0 }}>
                  {['Type','Title','Status','Created','Size','Agents','Vulns','Creds','Actions'].map(h=>(
                    <th key={h} style={{ padding:'6px 12px', color:'var(--tx1)', fontWeight:400, textAlign:'left', fontSize:9, textTransform:'uppercase', borderRight:'1px solid #0d0d0d', whiteSpace:'nowrap' }}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {MOCK_REPORTS.map(r=>(
                  <tr key={r.id} style={{ borderBottom:'1px solid #0a0a0a', cursor:'pointer' }}
                    onMouseEnter={e=>(e.currentTarget.style.background='#0d0d0d')}
                    onMouseLeave={e=>(e.currentTarget.style.background='transparent')}
                    onClick={()=>setSelRep(r)}>
                    <td style={{ padding:'7px 12px', borderRight:'1px solid #0a0a0a' }}>
                      <span style={{ fontSize:9, padding:'2px 6px', border:`1px solid ${TYPE_COL[r.type]}44`, color:TYPE_COL[r.type] }}>{r.type.slice(0,12)}</span>
                    </td>
                    <td style={{ padding:'7px 12px', color:'#aaaaaa', borderRight:'1px solid #0a0a0a', fontWeight:700 }}>{r.title}</td>
                    <td style={{ padding:'7px 12px', borderRight:'1px solid #0a0a0a' }}>
                      <span style={{ color:STATUS_COL[r.status], fontSize:11 }}>[{r.status}]</span>
                    </td>
                    <td style={{ padding:'7px 12px', color:'var(--tx1)', borderRight:'1px solid #0a0a0a', fontSize:10, whiteSpace:'nowrap' }}>{r.created}</td>
                    <td style={{ padding:'7px 12px', color:'#777', borderRight:'1px solid #0a0a0a' }}>{r.size}</td>
                    <td style={{ padding:'7px 12px', color:'#e05c6e', borderRight:'1px solid #0a0a0a', textAlign:'center' }}>{r.agents}</td>
                    <td style={{ padding:'7px 12px', color:'#d48b55', borderRight:'1px solid #0a0a0a', textAlign:'center' }}>{r.vulns}</td>
                    <td style={{ padding:'7px 12px', color:'#5bb8d4', borderRight:'1px solid #0a0a0a', textAlign:'center' }}>{r.creds}</td>
                    <td style={{ padding:'7px 12px' }}>
                      <div style={{ display:'flex', gap:4 }}>
                        <button onClick={e=>e.stopPropagation()} style={{ background:'#0a1a0a', border:'1px solid #33a84a', color:'#33a84a', fontFamily:'Courier New', fontSize:9, padding:'2px 6px', cursor:'pointer' }}>Export</button>
                        <button onClick={e=>e.stopPropagation()} style={{ background:'transparent', border:'1px solid #1a1a1a', color:'var(--tx1)', fontFamily:'Courier New', fontSize:9, padding:'2px 6px', cursor:'pointer' }}>View</button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {/* DETAIL SIDE */}
          {selRep && (
            <div style={{ width:300,background:'var(--inset2)',borderLeft:'1px solid #111',display:'flex',flexDirection:'column',overflow:'hidden',flexShrink:0 }}>
              <div style={{ padding:'5px 12px',background:'var(--inset)',borderBottom:'1px solid #0d0d0d',display:'flex',justifyContent:'space-between',alignItems:'center' }}>
                <span style={{ fontSize:10,color:'var(--tx1)',textTransform:'uppercase',letterSpacing:1 }}>Report Detail</span>
                <button onClick={()=>setSelRep(null)} style={{ background:'transparent',border:'1px solid #1a1a1a',color:'var(--tx2)',fontFamily:'Courier New',fontSize:9,padding:'2px 7px',cursor:'pointer' }}>✕</button>
              </div>
              <div style={{ flex:1,overflowY:'auto',padding:'14px' }}>
                <div style={{ fontSize:14,fontWeight:700,color:'#e8e8e8',marginBottom:12 }}>{selRep.title}</div>
                {[['Type',selRep.type],['Status',selRep.status],['Created',selRep.created],['Size',selRep.size],
                  ['Agents',String(selRep.agents)],['Vulns',String(selRep.vulns)],['Creds',String(selRep.creds)]
                ].map(([k,v])=>(
                  <div key={k} style={{ marginBottom:8,paddingBottom:6,borderBottom:'1px solid #0a0a0a' }}>
                    <div style={{ fontSize:8,color:'var(--tx2)',textTransform:'uppercase',letterSpacing:1,marginBottom:2 }}>{k}</div>
                    <div style={{ fontSize:11,color:k==='Status'?STATUS_COL[v]:k==='Type'?TYPE_COL[v]:'#aaaaaa' }}>{v}</div>
                  </div>
                ))}
                <div style={{ display:'flex',flexDirection:'column',gap:6,marginTop:14 }}>
                  <button style={{ background:'#0a1a0a',border:'1px solid #33a84a',color:'#33a84a',fontFamily:'Courier New',fontSize:11,padding:'7px',cursor:'pointer' }}>Export PDF</button>
                  <button style={{ background:'#0a0a1a',border:'1px solid #5bb8d4',color:'#5bb8d4',fontFamily:'Courier New',fontSize:11,padding:'7px',cursor:'pointer' }}>Export HTML</button>
                  <button style={{ background:'transparent',border:'1px solid #1a1a1a',color:'var(--tx1)',fontFamily:'Courier New',fontSize:11,padding:'7px',cursor:'pointer' }}>Regenerate</button>
                  <button onClick={()=>setTab('builder')} style={{ background:'#1a0000',border:'1px solid #e05c6e',color:'#e05c6e',fontFamily:'Courier New',fontSize:11,padding:'7px',cursor:'pointer' }}>Edit in Builder</button>
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      {tab === 'builder' && (
        <div style={{ flex:1, display:'flex', overflow:'hidden' }}>
          {/* CONFIG */}
          <div style={{ width:320, background:'var(--inset2)', borderRight:'1px solid #111', display:'flex', flexDirection:'column', overflow:'hidden', flexShrink:0 }}>
            <div style={{ padding:'5px 12px', background:'var(--inset)', borderBottom:'1px solid #0d0d0d', fontSize:10, color:'var(--tx1)', textTransform:'uppercase', letterSpacing:1 }}>Report Configuration</div>
            <div style={{ flex:1, overflowY:'auto', padding:'14px' }}>

              <div style={{ marginBottom:14 }}>
                <div style={{ fontSize:9,color:'var(--tx1)',textTransform:'uppercase',letterSpacing:'1px',marginBottom:6 }}>Report Title</div>
                <input value={repTitle} onChange={e=>setRepTitle(e.target.value)} className="zk-input"/>
              </div>

              <div style={{ marginBottom:14 }}>
                <div style={{ fontSize:9,color:'var(--tx1)',textTransform:'uppercase',letterSpacing:'1px',marginBottom:6 }}>Report Type</div>
                <select value={repType} onChange={e=>setRepType(e.target.value)} className="zk-select">
                  {['Campaign Summary','Vulnerability Report','Network Recon','Credential Dump','Executive Summary','Technical Detail'].map(t=>(
                    <option key={t}>{t}</option>
                  ))}
                </select>
              </div>

              <div style={{ marginBottom:14 }}>
                <div style={{ fontSize:9,color:'var(--tx1)',textTransform:'uppercase',letterSpacing:'1px',marginBottom:6 }}>Output Format</div>
                <div style={{ display:'flex', gap:4 }}>
                  {(['PDF','HTML','MD','JSON'] as const).map(f=>(
                    <button key={f} onClick={()=>setFormat(f)} style={{
                      flex:1, background:format===f?'#1a0000':'#0d0d0d',
                      border:`1px solid ${format===f?'#e05c6e':'#111'}`,
                      color:format===f?'#e05c6e':'#555', fontFamily:'Courier New',
                      fontSize:11, padding:'5px', cursor:'pointer',
                    }}>{f}</button>
                  ))}
                </div>
              </div>

              <div style={{ marginBottom:14 }}>
                <div style={{ fontSize:9,color:'var(--tx1)',textTransform:'uppercase',letterSpacing:'1px',marginBottom:8 }}>Sections to Include</div>
                {SECTIONS.map(sec=>(
                  <div key={sec.key} onClick={()=>toggleSec(sec.key)}
                    style={{ display:'flex',alignItems:'flex-start',gap:10,padding:'6px 8px',marginBottom:3,cursor:'pointer',
                      background:selSecs.includes(sec.key)?'#120000':'transparent',
                      border:`1px solid ${selSecs.includes(sec.key)?'#e05c6e22':'#0d0d0d'}` }}
                    onMouseEnter={e=>(e.currentTarget.style.background=selSecs.includes(sec.key)?'#1a0000':'#0d0d0d')}
                    onMouseLeave={e=>(e.currentTarget.style.background=selSecs.includes(sec.key)?'#120000':'transparent')}>
                    <span style={{ fontSize:10,color:selSecs.includes(sec.key)?'#e05c6e':'#333',marginTop:1,flexShrink:0,fontWeight:700 }}>{selSecs.includes(sec.key)?'[✓]':'[ ]'}</span>
                    <div>
                      <div style={{ fontSize:11,color:selSecs.includes(sec.key)?'#aaaaaa':'#555' }}>{sec.label}</div>
                      <div style={{ fontSize:9,color:'var(--tx2)' }}>{sec.desc}</div>
                    </div>
                  </div>
                ))}
              </div>

              <div style={{ marginBottom:14 }}>
                <div style={{ fontSize:9,color:'var(--tx1)',textTransform:'uppercase',letterSpacing:'1px',marginBottom:6 }}>Data Sources</div>
                {['Include all agents','Include all credentials','Include all loot files','Include scan results','Include timeline'].map(s=>(
                  <div key={s} style={{ display:'flex',alignItems:'center',gap:8,marginBottom:6 }}>
                    <input type="checkbox" defaultChecked style={{ accentColor:'#e05c6e' }}/>
                    <span style={{ fontSize:11,color:'#777' }}>{s}</span>
                  </div>
                ))}
              </div>
            </div>

            <div style={{ padding:'10px 12px', borderTop:'1px solid #111', flexShrink:0 }}>
              <button onClick={generate} disabled={building} style={{
                width:'100%', padding:'10px', fontSize:12, fontWeight:700, letterSpacing:1,
                fontFamily:'Courier New', cursor:building?'default':'pointer',
                background:building?'#0d0d0d':'#1a0000',
                border:`1px solid ${building?'#222':'#e05c6e'}`,
                color:building?'#333':'#e05c6e',
              }}>{building?'[ GENERATING... ]':built?'[ REGENERATE ]':'[ GENERATE REPORT ]'}</button>
            </div>
          </div>

          {/* PREVIEW */}
          <div style={{ flex:1, display:'flex', flexDirection:'column', overflow:'hidden', background:'var(--inset2)' }}>
            <div style={{ padding:'5px 12px', background:'var(--inset)', borderBottom:'1px solid #0d0d0d', fontSize:10, color:'var(--tx1)', textTransform:'uppercase', letterSpacing:1, display:'flex', alignItems:'center', gap:10 }}>
              <span>Preview / Output</span>
              {built && <span style={{ color:'#33a84a' }}>● Generated</span>}
              {built && (
                <div style={{ marginLeft:'auto', display:'flex', gap:6 }}>
                  <button style={{ background:'#0a1a0a', border:'1px solid #33a84a', color:'#33a84a', fontFamily:'Courier New', fontSize:10, padding:'2px 10px', cursor:'pointer' }}>Export {format}</button>
                  <button style={{ background:'transparent', border:'1px solid #111', color:'var(--tx1)', fontFamily:'Courier New', fontSize:10, padding:'2px 10px', cursor:'pointer' }}>Save to Library</button>
                </div>
              )}
            </div>
            <div style={{ flex:1, overflowY:'auto', padding:'20px 24px', fontFamily:'Courier New', fontSize:12 }}>
              {!built && !building && (
                <div style={{ color:'var(--tx3)' }}>[*] Configure sections and generate report</div>
              )}
              {building && (
                <div>
                  {['[*] Collecting agent session data...','[*] Aggregating credential records...','[*] Compiling vulnerability findings...','[*] Building network topology section...','[*] Generating executive summary...','[*] Rendering output...'].map((l,i)=>(
                    <div key={i} style={{ color:'#33a84a', marginBottom:6 }}>{l}</div>
                  ))}
                  <div style={{ color:'#e05c6e' }}>Generating {format}...<span className="cursor"/></div>
                </div>
              )}
              {built && (
                <div>
                  <div style={{ borderBottom:'1px solid #1a1a1a', paddingBottom:16, marginBottom:20 }}>
                    <div style={{ fontSize:18, color:'#e8e8e8', fontWeight:700, marginBottom:6 }}>{repTitle}</div>
                    <div style={{ fontSize:10, color:'var(--tx1)' }}>Type: {repType} · Format: {format} · Generated: {new Date().toISOString().slice(0,16).replace('T',' ')} UTC</div>
                    <div style={{ fontSize:10, color:'var(--tx1)', marginTop:3 }}>Sections: {selSecs.length} / {SECTIONS.length} · Data: 6 agents, 11 vulns, 8 creds, 12 loot files</div>
                  </div>
                  {selSecs.map(k => {
                    const sec = SECTIONS.find(s=>s.key===k);
                    if (!sec) return null;
                    return (
                      <div key={k} style={{ marginBottom:16, padding:'12px 14px', background:'var(--inset2)', border:'1px solid #111' }}>
                        <div style={{ fontSize:12, color:'#e05c6e', fontWeight:700, marginBottom:6, textTransform:'uppercase', letterSpacing:1 }}>{sec.label}</div>
                        <div style={{ fontSize:11, color:'var(--tx1)' }}>{sec.desc}</div>
                        <div style={{ fontSize:10, color:'var(--tx2)', marginTop:6 }}>[Content populated from live data — wire to /api/report/generate]</div>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
