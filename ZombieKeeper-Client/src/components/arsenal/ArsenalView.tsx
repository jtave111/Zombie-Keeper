import { useState } from 'react';

type Domain = 'network-session'|'agents'|'libs';
type BuildStatus = 'built'|'building'|'outdated'|'not-built'|'planned';

interface ArsenalTool {
  id: string; domain: Domain; name: string; binary: string;
  desc: string; status: BuildStatus; lastBuild?: string;
  size?: string; caps?: string[]; deps: string[];
}

const STATUS_COLOR: Record<BuildStatus,string> = {
  built:'#33a84a', building:'#d48b55', outdated:'#c8a84b', 'not-built':'#444', planned:'#2a2a2a',
};

const TOOLS: ArsenalTool[] = [
  {
    id:'local-fingerprint', domain:'network-session', name:'LocalFingerPrint', binary:'build/network-session/scanners/local-fingerprint/cpp/LocalFingerPrint',
    desc:'Full subnet fingerprint: ICMP sweep + TCP port scan + service enumeration. Feeds /api/recon.',
    status:'not-built', deps:['ping','net_utils'], caps:['CAP_NET_RAW','CAP_NET_ADMIN'],
  },
  {
    id:'libping', domain:'libs', name:'libping.a', binary:'build/libs/cpp/ping/libping.a',
    desc:'Static library — ICMP raw socket ping. Shared across domains.',
    status:'not-built', deps:['net_utils'], lastBuild:undefined,
  },
  {
    id:'libnet_utils', domain:'libs', name:'libnet_utils.a', binary:'build/libs/cpp/net_utils/libnet_utils.a',
    desc:'ICMP checksum and common socket utilities. Base lib.',
    status:'not-built', deps:[],
  },
  {
    id:'ddos', domain:'agents', name:'D_DOS', binary:'build/agents/attacks/D_DOS',
    desc:'TCP flood + ICMP ping flood — uses net_utils + ping. Planned.',
    status:'planned', deps:['ping','net_utils'],
  },
  {
    id:'beacon-linux', domain:'agents', name:'beacon-linux', binary:'build/agents/implants/linux/beacon',
    desc:'ELF beacon with HTTP/DNS callbacks. Registers against Agent model.',
    status:'planned', deps:[],
  },
  {
    id:'beacon-windows', domain:'agents', name:'beacon-windows', binary:'build/agents/implants/windows/beacon.exe',
    desc:'PE beacon for Windows — reflective loader, hollow process variants.',
    status:'planned', deps:[],
  },
  {
    id:'shellcode-x64', domain:'agents', name:'shellcode-x64', binary:'build/agents/payloads/x86_64/shellcode.bin',
    desc:'Position-independent shellcode for x86_64. Stager + full payload variants.',
    status:'planned', deps:[],
  },
];

const DOMAIN_COLOR: Record<Domain,string> = { 'network-session':'#5a96d4', agents:'#e05c6e', libs:'#c8a84b' };

const BUILD_LOG: Record<string,string[]> = {
  'local-fingerprint':[
    '[*] Configuring cmake (Debug)...',
    '[*] Compiling LocalFingerPrint...',
    '[+] libnet_utils.a → OK',
    '[+] libping.a → OK',
    '[+] LocalFingerPrint → OK',
    '[!] Run: sudo cmake --build build --target setcap',
    '[+] Binary: build/network-session/scanners/local-fingerprint/cpp/LocalFingerPrint',
  ],
};

export default function ArsenalView() {
  const [tools,     setTools]   = useState<ArsenalTool[]>(TOOLS);
  const [selected,  setSelected]= useState<ArsenalTool>(TOOLS[0]);
  const [buildLog,  setBuildLog]= useState<string[]>([]);
  const [building,  setBuilding]= useState<string|null>(null);
  const [domainFilter, setDF]   = useState<Domain|'all'>('all');

  const visible = tools.filter(t => domainFilter==='all' || t.domain===domainFilter);

  const triggerBuild = (tool: ArsenalTool) => {
    if (tool.status === 'planned') return;
    setBuilding(tool.id);
    setBuildLog([]);
    const lines = BUILD_LOG[tool.id] ?? [
      `[*] cmake --build build --target ${tool.name}`,
      '[+] Compiling...',
      '[+] Done.',
    ];
    lines.forEach((line,i) => {
      setTimeout(()=>{
        setBuildLog(p=>[...p,line]);
        if (i === lines.length-1) {
          setBuilding(null);
          setTools(p=>p.map(t=>t.id===tool.id?{...t,status:'built',lastBuild:new Date().toISOString().slice(0,16),size:'248 KB'}:t));
        }
      }, (i+1)*300 + Math.random()*100);
    });
  };

  const buildAll = () => {
    const buildable = tools.filter(t=>t.status!=='planned');
    buildable.forEach((t,i)=>setTimeout(()=>triggerBuild(t), i*2000));
  };

  return (
    <div style={{ display:'flex', height:'100%', overflow:'hidden', fontFamily:'Courier New' }}>

      {/* LEFT — tool list */}
      <div style={{ width:240, background:'var(--inset2)', borderRight:'1px solid #1a1a1a', display:'flex', flexDirection:'column', flexShrink:0 }}>
        <div style={{ padding:'8px 10px', borderBottom:'1px solid #1a1a1a', display:'flex', alignItems:'center', gap:8 }}>
          <span style={{ fontSize:9, color:'var(--tx2)', textTransform:'uppercase', letterSpacing:1 }}>Arsenal</span>
          <span style={{ fontSize:9, color:'#33a84a', marginLeft:'auto' }}>{tools.filter(t=>t.status==='built').length}/{tools.filter(t=>t.status!=='planned').length} built</span>
        </div>

        {/* Domain filter */}
        <div style={{ display:'flex', gap:0, borderBottom:'1px solid #1a1a1a', flexShrink:0 }}>
          {(['all','network-session','agents','libs'] as const).map(d=>(
            <button key={d} onClick={()=>setDF(d)} style={{
              flex:1, background:domainFilter===d?'#141414':'transparent',
              border:'none', borderRight:'1px solid #111',
              color: domainFilter===d ? 'var(--tx0)' : 'var(--tx2)',
              fontFamily:'Courier New', fontSize:8, padding:'4px 2px', cursor:'pointer', textTransform:'uppercase',
            }}>{d==='all'?'ALL':d==='network-session'?'NET':d==='agents'?'AGT':'LIBS'}</button>
          ))}
        </div>

        <div style={{ flex:1, overflowY:'auto' }}>
          {visible.map(t=>(
            <div key={t.id} onClick={()=>setSelected(t)} style={{
              padding:'8px 10px', borderBottom:'1px solid #111', cursor:'pointer',
              background: selected.id===t.id?'#0a0a14':'transparent',
              borderLeft:`2px solid ${selected.id===t.id?DOMAIN_COLOR[t.domain]:'transparent'}`,
              opacity: t.status==='planned'?0.5:1,
            }}>
              <div style={{ display:'flex', alignItems:'center', gap:6, marginBottom:3 }}>
                <span style={{ fontSize:9, color:DOMAIN_COLOR[t.domain], fontWeight:700, border:`1px solid ${DOMAIN_COLOR[t.domain]}44`, padding:'1px 4px', textTransform:'uppercase' }}>
                  {t.domain==='network-session'?'NET':t.domain==='agents'?'AGT':'LIB'}
                </span>
                <span style={{ fontSize:11, color:selected.id===t.id?'#ccc':'#666', fontWeight:700 }}>{t.name}</span>
              </div>
              <div style={{ display:'flex', alignItems:'center', gap:6 }}>
                <span style={{ fontSize:9, color:STATUS_COLOR[t.status] }}>● {t.status}</span>
                {t.lastBuild && <span style={{ fontSize:9, color:'var(--tx2)' }}>{t.lastBuild.slice(11)}</span>}
                {building===t.id && <span style={{ fontSize:9, color:'#d48b55', animation:'pulse 1s infinite' }}>BUILDING…</span>}
              </div>
            </div>
          ))}
        </div>

        <div style={{ padding:'8px 10px', borderTop:'1px solid #1a1a1a', flexShrink:0 }}>
          <button onClick={buildAll} style={{ width:'100%', background:'#1a0000', border:'1px solid #e05c6e', color:'#e05c6e', fontFamily:'Courier New', fontSize:10, padding:'5px', cursor:'pointer' }}>
            [ BUILD ALL ]
          </button>
        </div>
      </div>

      {/* RIGHT — tool detail */}
      <div style={{ flex:1, display:'flex', flexDirection:'column', overflow:'hidden' }}>

        {/* Tool header */}
        <div style={{ padding:'10px 14px', background:'var(--inset2)', borderBottom:'1px solid #1a1a1a', flexShrink:0 }}>
          <div style={{ display:'flex', alignItems:'center', gap:10, marginBottom:6 }}>
            <span style={{ fontSize:14, color:'#cccccc', fontWeight:700 }}>{selected.name}</span>
            <span style={{ fontSize:9, color:DOMAIN_COLOR[selected.domain], border:`1px solid ${DOMAIN_COLOR[selected.domain]}44`, padding:'2px 8px', textTransform:'uppercase' }}>{selected.domain}</span>
            <span style={{ fontSize:9, color:STATUS_COLOR[selected.status], marginLeft:'auto' }}>● {selected.status.toUpperCase()}</span>
          </div>
          <div style={{ fontSize:11, color:'var(--tx1)', marginBottom:8 }}>{selected.desc}</div>
          <div style={{ display:'flex', gap:16, fontSize:10 }}>
            <div>
              <span style={{ color:'var(--tx2)' }}>binary: </span>
              <span style={{ color:'var(--tx2)', fontFamily:'monospace' }}>{selected.binary}</span>
            </div>
            {selected.size && <div><span style={{ color:'var(--tx2)' }}>size: </span><span style={{ color:'var(--tx2)' }}>{selected.size}</span></div>}
          </div>
          {selected.deps.length > 0 && (
            <div style={{ marginTop:6, display:'flex', gap:6 }}>
              <span style={{ fontSize:9, color:'var(--tx2)' }}>deps:</span>
              {selected.deps.map(d=><span key={d} style={{ fontSize:9, color:'var(--tx2)', border:'1px solid #1a1a1a', padding:'1px 6px' }}>{d}</span>)}
            </div>
          )}
          {selected.caps && (
            <div style={{ marginTop:4, display:'flex', gap:6 }}>
              <span style={{ fontSize:9, color:'var(--tx2)' }}>caps:</span>
              {selected.caps.map(c=><span key={c} style={{ fontSize:9, color:'#c8a84b', border:'1px solid #2a2a1a', padding:'1px 6px' }}>{c}</span>)}
            </div>
          )}
        </div>

        {/* Build buttons */}
        <div style={{ padding:'8px 14px', background:'var(--inset2)', borderBottom:'1px solid #1a1a1a', display:'flex', gap:8, flexShrink:0 }}>
          <button
            onClick={()=>triggerBuild(selected)}
            disabled={building!==null || selected.status==='planned'}
            style={{ background: selected.status==='planned'?'#0d0d0d':'#1a0000', border:`1px solid ${selected.status==='planned'?'#111':'#e05c6e'}`, color:selected.status==='planned'?'#1a1a1a':'#e05c6e', fontFamily:'Courier New', fontSize:10, padding:'4px 16px', cursor:selected.status==='planned'?'default':'pointer' }}>
            {building===selected.id?'[ BUILDING... ]':selected.status==='planned'?'[ PLANNED ]':'[ BUILD ]'}
          </button>
          {selected.caps && (
            <button style={{ background:'#0a0a00', border:'1px solid #c8a84b', color:'#c8a84b', fontFamily:'Courier New', fontSize:10, padding:'4px 16px', cursor:'pointer' }}>
              [ SETCAP ]
            </button>
          )}
          <button onClick={()=>setBuildLog([])} style={{ background:'transparent', border:'1px solid #1a1a1a', color:'var(--tx2)', fontFamily:'Courier New', fontSize:10, padding:'4px 16px', cursor:'pointer' }}>
            [ CLEAR LOG ]
          </button>
          <span style={{ marginLeft:'auto', fontSize:10, color:'var(--tx2)', alignSelf:'center' }}>
            {selected.lastBuild ? `last: ${selected.lastBuild}` : 'never built'}
          </span>
        </div>

        {/* Build log */}
        <div style={{ flex:1, overflowY:'auto', padding:'10px 14px', background:'var(--inset2)' }}>
          <div style={{ fontSize:9, color:'var(--tx3)', textTransform:'uppercase', letterSpacing:1, marginBottom:8 }}>Build Output</div>
          {buildLog.length === 0 && (
            <div style={{ fontSize:10, color:'var(--tx3)' }}>No build output — click BUILD to compile</div>
          )}
          {buildLog.map((line,i)=>(
            <div key={i} style={{ fontSize:11, color: line.startsWith('[+]')?'#33a84a':line.startsWith('[-]')?'#e05c6e':line.startsWith('[!]')?'#c8a84b':'#555', lineHeight:1.7, fontFamily:'monospace' }}>
              {line}
            </div>
          ))}
        </div>

        {/* Build reference */}
        <div style={{ padding:'8px 14px', background:'var(--inset2)', borderTop:'1px solid #1a1a1a', flexShrink:0 }}>
          <div style={{ fontSize:9, color:'var(--tx3)', marginBottom:4, textTransform:'uppercase', letterSpacing:1 }}>Quick Commands</div>
          <div style={{ display:'flex', gap:12, fontSize:10, fontFamily:'monospace' }}>
            <span style={{ color:'var(--tx2)' }}>make network-session</span>
            <span style={{ color:'var(--tx2)' }}>·</span>
            <span style={{ color:'var(--tx2)' }}>make agents</span>
            <span style={{ color:'var(--tx2)' }}>·</span>
            <span style={{ color:'var(--tx2)' }}>make clean</span>
            <span style={{ color:'var(--tx2)' }}>·</span>
            <span style={{ color:'var(--tx2)' }}>make reset</span>
          </div>
        </div>
      </div>
    </div>
  );
}
