'use client';
import { useState, useRef, useEffect } from 'react';
import { NetworkSession, NetworkNode } from '@/lib/networkData';
import ScannerView from '../scanner/ScannerView';

type Tab = 'topology' | 'scanner' | 'admin';

const SEV_COL: Record<string,string> = { CRITICAL:'#e05c6e', HIGH:'#d48b55', MEDIUM:'#c8a84b', LOW:'#5bb8d4', INFO:'#444' };
const SEV_BG:  Record<string,string> = { CRITICAL:'#140408', HIGH:'#140d04', MEDIUM:'#141004', LOW:'#041014', INFO:'#0d0d0d' };

function nodeRiskColor(n: NetworkNode) {
  if (n.vulnerabilityScore >= 70) return '#e05c6e';
  if (n.vulnerabilityScore >= 40) return '#d48b55';
  return '#33a84a';
}

function ScoreBar({ score }: { score: number }) {
  const col = score >= 70 ? '#e05c6e' : score >= 40 ? '#d48b55' : '#33a84a';
  return (
    <div style={{ display:'flex', alignItems:'center', gap:8 }}>
      <div style={{ width:80, height:3, background:'#0d0d0d', position:'relative' }}>
        <div style={{ width:`${score}%`, height:3, background:col, position:'absolute', top:0, left:0 }}/>
      </div>
      <span style={{ fontSize:11, color:col, fontFamily:'Courier New', fontWeight:700, minWidth:24 }}>{score}</span>
    </div>
  );
}

export default function NetworkView() {
  const [tab,      setTab]      = useState<Tab>('topology');
  // Sessions will be fetched when the backend exposes GET /c2-server/sessions
  const sessions: NetworkSession[] = [];
  const [selSess,  setSelSess]  = useState('');
  const [selNode,  setSelNode]  = useState<NetworkNode | null>(null);
  const [scanNode, setScanNode] = useState<NetworkNode | null>(null);
  const [adminSub, setAdminSub] = useState<'nodes'|'vulns'|'ports'|'stats'>('nodes');
  const [search,   setSearch]   = useState('');
  const svgRef   = useRef<SVGSVGElement>(null);
  const [sz, setSz] = useState({ w:700, h:500 });
  const [tick, setTick] = useState(0);
  const animRef = useRef<any>(null);

  useEffect(() => {
    animRef.current = setInterval(() => setTick(v => v+1), 55);
    return () => clearInterval(animRef.current);
  }, []);

  useEffect(() => {
    const upd = () => { if(svgRef.current){ const r=svgRef.current.getBoundingClientRect(); setSz({w:r.width,h:r.height}); }};
    upd(); window.addEventListener('resize',upd); return ()=>window.removeEventListener('resize',upd);
  }, []);

  const session = sessions.find(s=>s.id===selSess) ?? sessions[0] ?? null;
  const nodes   = session?.nodes ?? [];
  const pulse   = (Math.sin(tick*0.11)+1)/2;
  const {w,h}   = sz;
  const cx=w/2, cy=h/2;
  const R = Math.min(w,h)*0.30;

  const positions = nodes.map((node,i)=>{
    const angle = (i/nodes.length)*2*Math.PI - Math.PI/2;
    return { node, x:cx+R*Math.cos(angle), y:cy+R*Math.sin(angle) };
  });

  // Switch to scanner tab when node scan requested
  useEffect(() => {
    if (scanNode) setTab('scanner');
  }, [scanNode]);

  // Admin data
  const allNodes = session?.nodes ?? [];
  const allVulns = allNodes.flatMap(n=>n.vulnerabilities.map(v=>({...v,node:n})));
  const allPorts = allNodes.flatMap(n=>n.ports.map(p=>({...p,node:n})));

  return (
    <div style={{ display:'flex', flexDirection:'column', height:'100%', overflow:'hidden', background:'#080808' }}>

      {/* TAB BAR */}
      <div style={{ display:'flex', alignItems:'center', padding:'0 12px', background:'#0a0a0a', borderBottom:'1px solid #111', flexShrink:0, height:36, gap:4 }}>
        <span style={{ fontSize:10, color:'#1a1a1a', textTransform:'uppercase', letterSpacing:1, marginRight:10, fontFamily:'Courier New' }}>Network</span>
        {(['topology','scanner','admin'] as Tab[]).map(t=>(
          <button key={t} onClick={()=>{ setTab(t); if(t!=='scanner') setScanNode(null); }} style={{
            background:tab===t?'#1a0000':'transparent', border:`1px solid ${tab===t?'#e05c6e':'#111'}`,
            color:tab===t?'#e05c6e':'#333', fontFamily:'Courier New', fontSize:11,
            padding:'4px 14px', cursor:'pointer', textTransform:'uppercase', letterSpacing:0.8,
          }}>{t}{t==='scanner'&&scanNode?' ('+scanNode.ipv4+')':''}</button>
        ))}
        <select value={selSess} onChange={e=>{setSelSess(e.target.value);setSelNode(null);setScanNode(null);}}
          style={{ marginLeft:'auto', background:'#080808', border:'1px solid #111', color:'#444', fontFamily:'Courier New', fontSize:11, padding:'3px 8px', outline:'none' }}>
          {sessions.length === 0
            ? <option value="">— No sessions —</option>
            : sessions.map(s=><option key={s.id} value={s.id}>{s.networkName} — {s.cidr} ({s.networkInterface})</option>)}
        </select>
        <span style={{ fontSize:10, color:'#1a1a1a', fontFamily:'Courier New', marginLeft:8 }}>{session?.lastSeen?.slice(11,16)} UTC</span>
      </div>

      {/* ── TOPOLOGY ── */}
      {tab==='topology' && !session && (
        <div style={{ flex:1, display:'flex', alignItems:'center', justifyContent:'center', fontFamily:'Courier New', fontSize:11, color:'#2a2a2a' }}>
          [*] No network sessions — run a scan first
        </div>
      )}
      {tab==='topology' && session && (
        <div style={{ flex:1, display:'flex', overflow:'hidden' }}>

          {/* SVG */}
          <div style={{ flex:1, position:'relative', overflow:'hidden', background:'#050508' }}>
            <svg ref={svgRef} width="100%" height="100%" style={{ display:'block' }}>
              <defs>
                <radialGradient id="tbg" cx="50%" cy="50%" r="55%">
                  <stop offset="0%" stopColor="#08100c"/><stop offset="100%" stopColor="#030508"/>
                </radialGradient>
                <filter id="glow3"><feGaussianBlur stdDeviation="3" result="b"/><feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge></filter>
                <filter id="glow6"><feGaussianBlur stdDeviation="6" result="b"/><feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge></filter>
                <filter id="glow10"><feGaussianBlur stdDeviation="10" result="b"/><feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge></filter>
              </defs>
              <rect width="100%" height="100%" fill="url(#tbg)"/>

              {/* Radar rings */}
              {[R*0.35, R*0.65, R*1.0, R*1.35].map((r,i)=>(
                <circle key={i} cx={cx} cy={cy} r={r} fill="none" stroke="#0a1810" strokeWidth="0.8" strokeDasharray="4 10"/>
              ))}
              {/* Radar sweep line */}
              <line x1={cx} y1={cy} x2={cx} y2={cy-R*1.4}
                stroke="rgba(51,168,74,0.06)"
                strokeWidth="2"
                style={{ transformOrigin:`${cx}px ${cy}px`, transform:`rotate(${tick*2}deg)`, transition:'transform 0.05s linear' }}/>

              {/* Connection lines */}
              {positions.map(({node,x,y})=>{
                const col = nodeRiskColor(node);
                const isRisk = node.vulnerabilityScore >= 70;
                return (
                  <g key={`edge-${node.id}`}>
                    {/* Glow */}
                    <line x1={cx} y1={cy} x2={x} y2={y} stroke={col} strokeWidth="2" opacity={0.04}/>
                    {/* Main */}
                    <line x1={cx} y1={cy} x2={x} y2={y} stroke={col} strokeWidth={isRisk?0.8:0.5}
                      opacity={isRisk?0.35:0.2} strokeDasharray={isRisk?'5 5':undefined}/>
                    {/* Moving packet */}
                    <circle r="2" fill={col} opacity={0.65}>
                      <animateMotion dur={`${2.5+node.id*0.35}s`} repeatCount="indefinite">
                        <mpath href={`#epath-${node.id}`}/>
                      </animateMotion>
                    </circle>
                    <path id={`epath-${node.id}`} d={`M ${cx} ${cy} L ${x} ${y}`} fill="none" stroke="none"/>
                  </g>
                );
              })}

              {/* Gateway — center */}
              <circle cx={cx} cy={cy} r={32+pulse*6} fill="none" stroke="#e05c6e" strokeWidth="0.5" opacity={0.1}/>
              <circle cx={cx} cy={cy} r={22+pulse*3} fill="none" stroke="#e05c6e" strokeWidth="0.8" opacity={0.2}/>
              <circle cx={cx} cy={cy} r={16} fill="#120206" stroke="#e05c6e" strokeWidth="1.8" filter="url(#glow6)"/>
              <text x={cx} y={cy-2} textAnchor="middle" fontSize="9" fill="#e05c6e" fontFamily="Courier New" fontWeight="bold">GW</text>
              <text x={cx} y={cy+10} textAnchor="middle" fontSize="7.5" fill="#e05c6e" fontFamily="Courier New" opacity={0.5}>{session?.gatewayIp??''}</text>

              {/* Nodes */}
              {positions.map(({node,x,y})=>{
                const col  = nodeRiskColor(node);
                const isSel= selNode?.id === node.id;
                const isRisk= node.vulnerabilityScore >= 70;
                const isMed = node.vulnerabilityScore >= 40 && !isRisk;
                const R_node = 14;

                return (
                  <g key={node.id} onClick={()=>setSelNode(isSel?null:node)} style={{ cursor:'pointer' }}>
                    {/* Selection halo */}
                    {isSel && <circle cx={x} cy={y} r={R_node+10} fill="none" stroke={col} strokeWidth="1.2" opacity={0.5} strokeDasharray="4 3"/>}
                    {/* Risk pulse */}
                    {isRisk && <circle cx={x} cy={y} r={R_node+6+pulse*8} fill="none" stroke={col} strokeWidth="0.6" opacity={0.25-pulse*0.18}/>}
                    {/* Glow fill */}
                    <circle cx={x} cy={y} r={R_node+8} fill={col} opacity={isRisk?0.07+pulse*0.04:isMed?0.04:0.02} filter="url(#glow10)"/>
                    {/* Node circle */}
                    <circle cx={x} cy={y} r={R_node}
                      fill={isRisk?'#160408':isMed?'#140d04':'#080e0a'}
                      stroke={col} strokeWidth={isSel?2.2:1.4} filter="url(#glow3)"/>

                    {/* IP last octet */}
                    <text x={x} y={y+5} textAnchor="middle" fontSize="10" fill={col} fontFamily="Courier New" fontWeight="bold">
                      {node.ipv4.split('.').pop()}
                    </text>

                    {/* Agent badge */}
                    {node.isAgent && (
                      <g>
                        <rect x={x-14} y={y-R_node-14} width={28} height={10} fill="#1a0000" stroke="#e05c6e" strokeWidth="0.8" rx={1}/>
                        <text x={x} y={y-R_node-6} textAnchor="middle" fontSize="7" fill="#e05c6e" fontFamily="Courier New" fontWeight="bold">AGENT</text>
                      </g>
                    )}
                    {/* Untrusted badge */}
                    {!node.isTrusted && (
                      <g>
                        <rect x={x-18} y={y+R_node+4} width={36} height={10} fill="#140a00" stroke="#d48b55" strokeWidth="0.6" rx={1}/>
                        <text x={x} y={y+R_node+12} textAnchor="middle" fontSize="6.5" fill="#d48b55" fontFamily="Courier New">UNTRUSTED</text>
                      </g>
                    )}
                    {/* OS label */}
                    <text x={x} y={y+R_node+28} textAnchor="middle" fontSize="7.5" fill={col} fontFamily="Courier New" opacity={0.5}>
                      {node.os.slice(0,9)}
                    </text>
                    {/* Vuln score dot */}
                    {node.vulnerabilityScore > 0 && (
                      <circle cx={x+R_node-2} cy={y-R_node+2} r={4}
                        fill={col} opacity={0.8} stroke="#060606" strokeWidth="0.5"/>
                    )}
                  </g>
                );
              })}

              <text x="10" y="20" fontSize="8" fill="#0a1810" fontFamily="Courier New">
                {session?.networkName??''}{session?' — ':''}{session?.cidr??''}{session?` — ${nodes.length} nodes · gw: ${session.gatewayIp}`:''}
              </text>
            </svg>

            {/* Legend */}
            <div style={{ position:'absolute',bottom:12,left:12,background:'rgba(4,4,6,0.9)',border:'1px solid #0d0d0d',padding:'8px 12px',fontFamily:'Courier New',fontSize:10 }}>
              {[['#33a84a','Score < 40'],['#d48b55','Score 40-70'],['#e05c6e','Score > 70 / Risk']].map(([c,l])=>(
                <div key={l} style={{ display:'flex',alignItems:'center',gap:7,marginBottom:4 }}>
                  <span style={{ width:7,height:7,borderRadius:'50%',background:c as string,display:'inline-block',boxShadow:`0 0 4px ${c}` }}/>
                  <span style={{ color:'#333' }}>{l}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Side panel */}
          <div style={{ width:290,background:'#0a0a0a',borderLeft:'1px solid #111',display:'flex',flexDirection:'column',overflow:'hidden',flexShrink:0 }}>
            <div style={{ padding:'5px 10px',background:'#111',borderBottom:'1px solid #0d0d0d',fontSize:10,color:'#333',textTransform:'uppercase',letterSpacing:1 }}>
              {selNode ? `Node — ${selNode.ipv4}` : 'Node Detail'}
            </div>
            {selNode ? (
              <div style={{ flex:1,overflowY:'auto',padding:'12px' }}>
                {/* Header */}
                <div style={{ display:'flex',justifyContent:'space-between',alignItems:'flex-start',marginBottom:10 }}>
                  <div>
                    <div style={{ color:'#5bb8d4',fontFamily:'Courier New',fontSize:14,fontWeight:700 }}>{selNode.ipv4}</div>
                    <div style={{ color:'#333',fontSize:10,fontFamily:'Courier New',marginTop:2 }}>{selNode.hostname}</div>
                  </div>
                  <button onClick={()=>setSelNode(null)} style={{ background:'transparent',border:'1px solid #111',color:'#333',fontFamily:'Courier New',fontSize:9,padding:'2px 8px',cursor:'pointer' }}>✕</button>
                </div>

                <ScoreBar score={selNode.vulnerabilityScore}/>

                <div style={{ marginTop:10,display:'grid',gridTemplateColumns:'1fr 1fr',gap:'5px 12px' }}>
                  {[['OS',selNode.os],['Arch',selNode.architecture],['MAC',selNode.mac],['Vendor',selNode.vendor],
                    ['Status',selNode.status],['Trusted',selNode.isTrusted?'YES':'NO'],
                    ['Agent',selNode.isAgent?'YES':'NO'],['Ports',String(selNode.ports.length)]
                  ].map(([k,v])=>(
                    <div key={k} style={{ borderBottom:'1px solid #0a0a0a',paddingBottom:4 }}>
                      <div style={{ fontSize:8,color:'#222',fontFamily:'Courier New',textTransform:'uppercase',letterSpacing:0.8,marginBottom:2 }}>{k}</div>
                      <div style={{ fontSize:10,color:k==='Trusted'&&v==='NO'?'#d48b55':k==='Agent'&&v==='YES'?'#e05c6e':k==='Status'?v==='UP'?'#33a84a':'#e05c6e':'#666',fontFamily:'Courier New' }}>{v}</div>
                    </div>
                  ))}
                </div>

                {/* Ports */}
                <div style={{ marginTop:12,fontSize:8,color:'#222',textTransform:'uppercase',letterSpacing:1,marginBottom:6 }}>Ports ({selNode.ports.length})</div>
                {selNode.ports.map(p=>(
                  <div key={p.id} style={{ display:'flex',alignItems:'center',gap:8,padding:'4px 8px',marginBottom:4,background:'#060606',border:'1px solid #0d0d0d' }}>
                    <span style={{ color:'#e05c6e',fontFamily:'Courier New',fontSize:11,fontWeight:700,minWidth:40 }}>{p.number}</span>
                    <span style={{ color:'#333',fontSize:10,fontFamily:'Courier New',minWidth:32 }}>{p.proto?.toUpperCase()}</span>
                    <span style={{ color:'#555',fontSize:10,fontFamily:'Courier New',flex:1,overflow:'hidden',textOverflow:'ellipsis',whiteSpace:'nowrap' }}>{p.service}</span>
                  </div>
                ))}

                {/* Vulnerabilities */}
                {selNode.vulnerabilities.length > 0 && (
                  <>
                    <div style={{ marginTop:12,fontSize:8,color:'#222',textTransform:'uppercase',letterSpacing:1,marginBottom:6 }}>Vulnerabilities ({selNode.vulnerabilities.length})</div>
                    {selNode.vulnerabilities.map(v=>(
                      <div key={v.id} style={{ marginBottom:8,padding:'7px 10px',background:SEV_BG[v.severity],border:`1px solid ${SEV_COL[v.severity]}33` }}>
                        <div style={{ display:'flex',alignItems:'center',gap:6,marginBottom:4 }}>
                          <span style={{ fontSize:8,padding:'1px 6px',border:`1px solid ${SEV_COL[v.severity]}`,color:SEV_COL[v.severity],fontFamily:'Courier New',fontWeight:700 }}>{v.severity}</span>
                          {v.cveId && <span style={{ fontSize:9,color:'#5bb8d4',fontFamily:'Courier New' }}>{v.cveId}</span>}
                        </div>
                        <div style={{ fontSize:10,color:SEV_COL[v.severity],fontFamily:'Courier New',marginBottom:3 }}>{v.title}</div>
                        <div style={{ fontSize:9,color:'#33a84a',fontFamily:'Courier New' }}>▸ {v.recommendation}</div>
                      </div>
                    ))}
                  </>
                )}

                {/* Actions */}
                <div style={{ marginTop:14,display:'flex',gap:6 }}>
                  <button onClick={()=>setScanNode(selNode)} style={{ flex:1,background:'#1a0000',border:'1px solid #e05c6e',color:'#e05c6e',fontFamily:'Courier New',fontSize:11,padding:'7px',cursor:'pointer',fontWeight:700 }}>
                    ▶ Scan This Node
                  </button>
                  <button onClick={()=>setSelNode(null)} style={{ background:'transparent',border:'1px solid #111',color:'#333',fontFamily:'Courier New',fontSize:11,padding:'7px 10px',cursor:'pointer' }}>
                    ✕
                  </button>
                </div>
              </div>
            ) : (
              <>
                <div style={{ flex:1,overflowY:'auto' }}>
                  {positions.map(({node})=>{
                    const col = nodeRiskColor(node);
                    return (
                      <div key={node.id} onClick={()=>setSelNode(node)}
                        style={{ padding:'8px 12px',borderBottom:'1px solid #0d0d0d',cursor:'pointer' }}
                        onMouseEnter={e=>(e.currentTarget.style.background='#0d0d0d')}
                        onMouseLeave={e=>(e.currentTarget.style.background='transparent')}>
                        <div style={{ display:'flex',alignItems:'center',gap:8,marginBottom:3 }}>
                          <span style={{ width:6,height:6,borderRadius:'50%',background:col,flexShrink:0,boxShadow:`0 0 3px ${col}` }}/>
                          <span style={{ color:'#5bb8d4',fontFamily:'Courier New',fontSize:11,fontWeight:700,flex:1 }}>{node.ipv4}</span>
                          {node.isAgent && <span style={{ fontSize:8,padding:'0 5px',background:'#1a0000',border:'1px solid #e05c6e',color:'#e05c6e',fontFamily:'Courier New' }}>AGENT</span>}
                          {!node.isTrusted && <span style={{ fontSize:8,padding:'0 5px',background:'#140800',border:'1px solid #d48b55',color:'#d48b55',fontFamily:'Courier New' }}>!</span>}
                        </div>
                        <div style={{ display:'flex',alignItems:'center',gap:8,paddingLeft:14 }}>
                          <span style={{ fontSize:9,color:'#333',fontFamily:'Courier New',flex:1 }}>{node.hostname}</span>
                          <ScoreBar score={node.vulnerabilityScore}/>
                        </div>
                      </div>
                    );
                  })}
                </div>
                <div style={{ padding:'8px 12px',borderTop:'1px solid #0d0d0d',fontSize:9,color:'#1a1a1a',fontFamily:'Courier New' }}>
                  Click a node in the topology or list to inspect
                </div>
              </>
            )}
          </div>
        </div>
      )}

      {/* ── SCANNER ── */}
      {tab==='scanner' && <ScannerView targetNode={scanNode}/>}

      {/* ── ADMIN ── */}
      {tab==='admin' && (
        <div style={{ flex:1,display:'flex',overflow:'hidden' }}>
          {/* Left nav */}
          <div style={{ width:200,background:'#0a0a0a',borderRight:'1px solid #111',display:'flex',flexDirection:'column',overflow:'hidden',flexShrink:0 }}>
            <div style={{ padding:'5px 10px',background:'#111',borderBottom:'1px solid #0d0d0d',fontSize:10,color:'#333',textTransform:'uppercase',letterSpacing:1 }}>Network Admin</div>
            {[{k:'nodes',l:'Nodes',n:allNodes.length},{k:'vulns',l:'Vulnerabilities',n:allVulns.length},{k:'ports',l:'Port Registry',n:allPorts.length},{k:'stats',l:'Statistics',n:0}].map(item=>(
              <div key={item.k} onClick={()=>setAdminSub(item.k as any)}
                style={{ padding:'9px 12px',borderBottom:'1px solid #0a0a0a',cursor:'pointer',borderLeft:`2px solid ${adminSub===item.k?'#e05c6e':'transparent'}`,background:adminSub===item.k?'#100000':'transparent' }}
                onMouseEnter={e=>(e.currentTarget.style.background='#0d0d0d')}
                onMouseLeave={e=>(e.currentTarget.style.background=adminSub===item.k?'#100000':'transparent')}>
                <div style={{ fontSize:11,color:adminSub===item.k?'#e05c6e':'#666',fontFamily:'Courier New' }}>{item.l}</div>
                {item.n>0&&<div style={{ fontSize:9,color:'#2a2a2a',fontFamily:'Courier New',marginTop:2 }}>{item.n} entries</div>}
              </div>
            ))}
            <div style={{ marginTop:'auto',padding:'10px 12px',borderTop:'1px solid #0d0d0d' }}>
              {[['Subnet',session?.cidr??'—'],['Gateway',session?.gatewayIp??'—'],['Interface',session?.networkInterface??'—'],['Type',session?.networkType??'—']].map(([k,v])=>(
                <div key={k} style={{ marginBottom:6 }}>
                  <div style={{ fontSize:8,color:'#1a1a1a',fontFamily:'Courier New',textTransform:'uppercase',letterSpacing:1 }}>{k}</div>
                  <div style={{ fontSize:10,color:'#444',fontFamily:'Courier New' }}>{v}</div>
                </div>
              ))}
            </div>
          </div>

          {/* Content */}
          <div style={{ flex:1,display:'flex',flexDirection:'column',overflow:'hidden' }}>
            {/* Search bar */}
            <div style={{ display:'flex',alignItems:'center',padding:'5px 12px',background:'#080808',borderBottom:'1px solid #0d0d0d',flexShrink:0,gap:8 }}>
              <input value={search} onChange={e=>setSearch(e.target.value)} placeholder="filter..."
                style={{ background:'#060606',border:'1px solid #111',color:'#666',fontFamily:'Courier New',fontSize:11,padding:'3px 8px',outline:'none',width:200 }}/>
              <button onClick={()=>setSearch('')} style={{ background:'transparent',border:'1px solid #0d0d0d',color:'#222',fontFamily:'Courier New',fontSize:9,padding:'3px 8px',cursor:'pointer' }}>Clear</button>
              <div style={{ marginLeft:'auto',display:'flex',gap:8 }}>
                {allVulns.filter(v=>v.severity==='CRITICAL').length>0&&<span style={{ fontSize:10,color:'#e05c6e',fontFamily:'Courier New',border:'1px solid #e05c6e44',padding:'1px 8px' }}>{allVulns.filter(v=>v.severity==='CRITICAL').length} CRITICAL</span>}
                {allVulns.filter(v=>v.severity==='HIGH').length>0&&<span style={{ fontSize:10,color:'#d48b55',fontFamily:'Courier New',border:'1px solid #d48b5544',padding:'1px 8px' }}>{allVulns.filter(v=>v.severity==='HIGH').length} HIGH</span>}
              </div>
            </div>

            <div style={{ flex:1,overflow:'auto' }}>
              {adminSub==='nodes'&&(
                <table style={{ width:'100%',borderCollapse:'collapse',fontFamily:'Courier New',fontSize:11 }}>
                  <thead><tr style={{ background:'#0d0d0d',borderBottom:'1px solid #111',position:'sticky',top:0 }}>
                    {['Status','IPv4','Hostname','OS','Vendor','MAC','Trusted','Agent','Score','Ports','Vulns','Actions'].map(h=>(
                      <th key={h} style={{ padding:'6px 10px',color:'#1a1a1a',fontWeight:400,textAlign:'left',fontSize:9,textTransform:'uppercase',borderRight:'1px solid #080808',whiteSpace:'nowrap' }}>{h}</th>
                    ))}
                  </tr></thead>
                  <tbody>
                    {allNodes.filter(n=>!search||n.ipv4.includes(search)||n.hostname.toLowerCase().includes(search.toLowerCase())).map(n=>(
                      <tr key={n.id} style={{ borderBottom:'1px solid #080808',cursor:'pointer' }}
                        onMouseEnter={e=>(e.currentTarget.style.background='#0a0a0a')}
                        onMouseLeave={e=>(e.currentTarget.style.background='transparent')}>
                        <td style={{ padding:'6px 10px',borderRight:'1px solid #080808' }}>
                          <span style={{ width:5,height:5,borderRadius:'50%',background:n.status==='UP'?'#33a84a':'#444',display:'inline-block',marginRight:5 }}/>
                          <span style={{ color:n.status==='UP'?'#33a84a':'#444',fontSize:10 }}>{n.status}</span>
                        </td>
                        <td style={{ padding:'6px 10px',color:'#5bb8d4',borderRight:'1px solid #080808',fontWeight:700 }}>{n.ipv4}</td>
                        <td style={{ padding:'6px 10px',color:'#666',borderRight:'1px solid #080808' }}>{n.hostname}</td>
                        <td style={{ padding:'6px 10px',color:'#444',borderRight:'1px solid #080808',fontSize:10,whiteSpace:'nowrap' }}>{n.os}</td>
                        <td style={{ padding:'6px 10px',color:'#333',borderRight:'1px solid #080808',fontSize:10 }}>{n.vendor}</td>
                        <td style={{ padding:'6px 10px',color:'#2a2a2a',borderRight:'1px solid #080808',fontSize:10 }}>{n.mac}</td>
                        <td style={{ padding:'6px 10px',borderRight:'1px solid #080808',textAlign:'center' }}>
                          <span style={{ color:n.isTrusted?'#33a84a':'#d48b55' }}>{n.isTrusted?'✓':'✗'}</span>
                        </td>
                        <td style={{ padding:'6px 10px',borderRight:'1px solid #080808',textAlign:'center' }}>
                          {n.isAgent&&<span style={{ fontSize:8,padding:'0 5px',background:'#1a0000',border:'1px solid #e05c6e',color:'#e05c6e' }}>ZK</span>}
                        </td>
                        <td style={{ padding:'6px 10px',borderRight:'1px solid #080808' }}><ScoreBar score={n.vulnerabilityScore}/></td>
                        <td style={{ padding:'6px 10px',color:'#5bb8d4',borderRight:'1px solid #080808',textAlign:'center' }}>{n.ports.length}</td>
                        <td style={{ padding:'6px 10px',borderRight:'1px solid #080808',textAlign:'center' }}>
                          <span style={{ color:n.vulnerabilities.length>0?'#e05c6e':'#2a2a2a' }}>{n.vulnerabilities.length}</span>
                        </td>
                        <td style={{ padding:'6px 10px' }}>
                          <div style={{ display:'flex',gap:4 }}>
                            <button onClick={()=>setScanNode(n)} style={{ background:'#1a0000',border:'1px solid #e05c6e',color:'#e05c6e',fontFamily:'Courier New',fontSize:9,padding:'2px 7px',cursor:'pointer' }}>Scan</button>
                            <button onClick={()=>{setTab('topology');setTimeout(()=>setSelNode(n),50);}} style={{ background:'transparent',border:'1px solid #111',color:'#333',fontFamily:'Courier New',fontSize:9,padding:'2px 7px',cursor:'pointer' }}>View</button>
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}

              {adminSub==='vulns'&&(
                <div>
                  {(['CRITICAL','HIGH','MEDIUM','LOW'] as const).map(sev=>{
                    const items=allVulns.filter(v=>v.severity===sev&&(!search||v.title.toLowerCase().includes(search.toLowerCase())||v.node.ipv4.includes(search)));
                    if(!items.length) return null;
                    return (
                      <div key={sev}>
                        <div style={{ padding:'6px 14px',background:SEV_BG[sev],borderBottom:`1px solid ${SEV_COL[sev]}22`,display:'flex',alignItems:'center',gap:10,position:'sticky',top:0 }}>
                          <span style={{ fontSize:9,padding:'1px 8px',border:`1px solid ${SEV_COL[sev]}`,color:SEV_COL[sev],fontFamily:'Courier New',fontWeight:700 }}>{sev}</span>
                          <span style={{ fontSize:10,color:'#222',fontFamily:'Courier New' }}>{items.length} finding{items.length!==1?'s':''}</span>
                        </div>
                        <table style={{ width:'100%',borderCollapse:'collapse',fontFamily:'Courier New',fontSize:11 }}>
                          <thead><tr style={{ background:'#070707' }}>
                            {['Host','Title','CVE','Evidence','Recommendation'].map(h=>(
                              <th key={h} style={{ padding:'5px 12px',color:'#1a1a1a',fontWeight:400,textAlign:'left',fontSize:9,textTransform:'uppercase' }}>{h}</th>
                            ))}
                          </tr></thead>
                          <tbody>
                            {items.map(v=>(
                              <tr key={v.id} style={{ borderBottom:'1px solid #090909' }}
                                onMouseEnter={e=>(e.currentTarget.style.background='#0a0a0a')}
                                onMouseLeave={e=>(e.currentTarget.style.background='transparent')}>
                                <td style={{ padding:'6px 12px',color:'#5bb8d4',cursor:'pointer',whiteSpace:'nowrap' }}
                                  onClick={()=>{setTab('topology');setTimeout(()=>setSelNode(v.node),50);}}>{v.node.ipv4}</td>
                                <td style={{ padding:'6px 12px',color:'#666' }}>{v.title}</td>
                                <td style={{ padding:'6px 12px',color:'#5bb8d4',fontSize:10,whiteSpace:'nowrap' }}>{v.cveId||'—'}</td>
                                <td style={{ padding:'6px 12px',color:'#333',fontSize:10,maxWidth:200,overflow:'hidden',textOverflow:'ellipsis',whiteSpace:'nowrap' }}>{v.evidence}</td>
                                <td style={{ padding:'6px 12px',color:'#33a84a',fontSize:10 }}>{v.recommendation}</td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    );
                  })}
                </div>
              )}

              {adminSub==='ports'&&(
                <table style={{ width:'100%',borderCollapse:'collapse',fontFamily:'Courier New',fontSize:11 }}>
                  <thead><tr style={{ background:'#0d0d0d',borderBottom:'1px solid #111',position:'sticky',top:0 }}>
                    {['Host','Port','Protocol','Service','Banner'].map(h=>(
                      <th key={h} style={{ padding:'6px 12px',color:'#1a1a1a',fontWeight:400,textAlign:'left',fontSize:9,textTransform:'uppercase',borderRight:'1px solid #080808' }}>{h}</th>
                    ))}
                  </tr></thead>
                  <tbody>
                    {allPorts.filter(p=>!search||String(p.number).includes(search)||p.service.toLowerCase().includes(search.toLowerCase())||p.node.ipv4.includes(search))
                      .sort((a,b)=>a.number-b.number).map(p=>(
                      <tr key={`${p.node.id}-${p.number}`} style={{ borderBottom:'1px solid #080808' }}
                        onMouseEnter={e=>(e.currentTarget.style.background='#0a0a0a')}
                        onMouseLeave={e=>(e.currentTarget.style.background='transparent')}>
                        <td style={{ padding:'6px 12px',color:'#5bb8d4',borderRight:'1px solid #080808',cursor:'pointer',whiteSpace:'nowrap' }}
                          onClick={()=>{setTab('topology');setTimeout(()=>setSelNode(p.node),50);}}>{p.node.ipv4}</td>
                        <td style={{ padding:'6px 12px',color:'#e05c6e',borderRight:'1px solid #080808',fontWeight:700 }}>{p.number}</td>
                        <td style={{ padding:'6px 12px',color:'#333',borderRight:'1px solid #080808',fontSize:10 }}>{p.proto?.toUpperCase()||''}</td>
                        <td style={{ padding:'6px 12px',color:'#666',borderRight:'1px solid #080808' }}>{p.service}</td>
                        <td style={{ padding:'6px 12px',color:'#333',fontSize:10,maxWidth:350,overflow:'hidden',textOverflow:'ellipsis',whiteSpace:'nowrap' }}>{p.banner||'—'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}

              {adminSub==='stats'&&(
                <div style={{ padding:'16px' }}>
                  <div style={{ display:'grid',gridTemplateColumns:'repeat(3,1fr)',gap:10,marginBottom:20 }}>
                    {[
                      {l:'Total Nodes',v:allNodes.length,c:'#cccccc'},
                      {l:'Nodes UP',v:allNodes.filter(n=>n.status==='UP').length,c:'#33a84a'},
                      {l:'Nodes DOWN',v:allNodes.filter(n=>n.status==='DOWN').length,c:'#e05c6e'},
                      {l:'ZK Agents',v:allNodes.filter(n=>n.isAgent).length,c:'#e05c6e'},
                      {l:'Untrusted',v:allNodes.filter(n=>!n.isTrusted).length,c:'#d48b55'},
                      {l:'Total Ports',v:allPorts.length,c:'#5bb8d4'},
                      {l:'Total Vulns',v:allVulns.length,c:'#e05c6e'},
                      {l:'Critical',v:allVulns.filter(v=>v.severity==='CRITICAL').length,c:'#e05c6e'},
                      {l:'High',v:allVulns.filter(v=>v.severity==='HIGH').length,c:'#d48b55'},
                    ].map(s=>(
                      <div key={s.l} style={{ background:'#0a0a0a',border:'1px solid #0d0d0d',padding:'12px 14px' }}>
                        <div style={{ fontSize:9,color:'#222',fontFamily:'Courier New',textTransform:'uppercase',letterSpacing:1,marginBottom:6 }}>{s.l}</div>
                        <div style={{ fontSize:24,color:s.c,fontFamily:'Courier New',fontWeight:700 }}>{s.v}</div>
                      </div>
                    ))}
                  </div>
                  <div style={{ marginBottom:10,fontSize:9,color:'#222',fontFamily:'Courier New',textTransform:'uppercase',letterSpacing:1 }}>Vulnerability Score by Node</div>
                  {allNodes.sort((a,b)=>b.vulnerabilityScore-a.vulnerabilityScore).map(n=>(
                    <div key={n.id} style={{ display:'flex',alignItems:'center',gap:12,marginBottom:7,padding:'6px 10px',background:'#080808',border:'1px solid #0d0d0d' }}>
                      <span style={{ color:'#5bb8d4',fontFamily:'Courier New',fontSize:11,minWidth:110 }}>{n.ipv4}</span>
                      <span style={{ color:'#333',fontFamily:'Courier New',fontSize:10,minWidth:130,flex:0 }}>{n.hostname}</span>
                      <div style={{ flex:1 }}><ScoreBar score={n.vulnerabilityScore}/></div>
                      <span style={{ color:n.vulnerabilities.length>0?'#e05c6e':'#222',fontFamily:'Courier New',fontSize:10,minWidth:55 }}>{n.vulnerabilities.length} vulns</span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
