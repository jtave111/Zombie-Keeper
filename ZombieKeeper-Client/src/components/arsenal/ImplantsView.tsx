import { useState } from 'react';

type OS        = 'linux'|'windows'|'macos';
type Format    = 'elf'|'pe'|'shellcode'|'dll'|'staged'|'stageless';
type Protocol  = 'http'|'https'|'dns'|'tcp'|'icmp';
type Encoding  = 'none'|'xor'|'aes-256'|'chacha20'|'rc4';
type Inject    = 'self'|'remote'|'hollow'|'early-bird'|'module-stomp';
type PersistM  = 'none'|'registry-run'|'scheduled-task'|'cron'|'service'|'dll-hijack';

interface ImplantConfig {
  name: string; os: OS; format: Format;
  host: string; port: string; https: boolean;
  protocol: Protocol; interval: string; jitter: string;
  encoding: Encoding; key: string;
  inject: Inject; ppid: string;
  persist: PersistM;
  killDate: string; maxRetries: string; userAgent: string;
  sandbox: boolean; antiDebug: boolean; sleepMask: boolean; amsiPatch: boolean;
}

const DEF: ImplantConfig = {
  name:'payload_001', os:'windows', format:'pe',
  host:'192.168.5.81', port:'4444', https:false,
  protocol:'http', interval:'30', jitter:'20',
  encoding:'xor', key:'',
  inject:'hollow', ppid:'explorer.exe',
  persist:'registry-run',
  killDate:'2027-12-31', maxRetries:'5', userAgent:'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
  sandbox:true, antiDebug:true, sleepMask:true, amsiPatch:false,
};

const S = {
  label: { fontSize:9, color:'var(--tx2)', textTransform:'uppercase' as const, letterSpacing:1, marginBottom:3 },
  field: { width:'100%', background:'var(--inset2)', border:'1px solid var(--b1)', color:'var(--tx0)', fontFamily:'Courier New', fontSize:11, padding:'4px 8px', outline:'none', appearance:'none' as const, WebkitAppearance:'none' as const },
  section: { marginBottom:16 },
  sectionTitle: { fontSize:9, color:'var(--tx2)', textTransform:'uppercase' as const, letterSpacing:1.5, marginBottom:8, paddingBottom:4, borderBottom:'1px solid var(--b1)' },
  row: { display:'grid' as const, gridTemplateColumns:'1fr 1fr' as const, gap:8, marginBottom:8 },
  checkbox: { display:'flex' as const, alignItems:'center' as const, gap:6, cursor:'pointer' as const },
};

const FORMATS_BY_OS: Record<OS,Format[]> = {
  linux:   ['elf','shellcode','staged','stageless'],
  windows: ['pe','dll','shellcode','staged','stageless'],
  macos:   ['elf','shellcode','stageless'],
};

export default function ImplantsView() {
  const [cfg, setCfg] = useState<ImplantConfig>(DEF);
  const [generating, setGenerating] = useState(false);
  const [generated, setGenerated]   = useState(false);

  const set = <K extends keyof ImplantConfig>(k: K, v: ImplantConfig[K]) =>
    setCfg(p => ({ ...p, [k]: v }));

  const generate = () => {
    setGenerating(true);
    setGenerated(false);
    setTimeout(()=>{ setGenerating(false); setGenerated(true); }, 1800);
  };

  const formats = FORMATS_BY_OS[cfg.os];

  const summary = `${cfg.name}.${cfg.format==='pe'?'exe':cfg.format==='dll'?'dll':cfg.format==='elf'?'elf':cfg.format==='shellcode'?'bin':'bin'}`;

  return (
    <div style={{ display:'flex', height:'100%', overflow:'hidden', fontFamily:'Courier New' }}>

      {/* Config column */}
      <div style={{ flex:1, overflowY:'auto', padding:'12px 16px', borderRight:'1px solid #1a1a1a' }}>
        <div style={{ fontSize:9, color:'var(--tx2)', textTransform:'uppercase', letterSpacing:1, marginBottom:12 }}>Implant / Beacon Builder</div>

        {/* Name + OS */}
        <div style={S.section}>
          <div style={S.sectionTitle}>Identity</div>
          <div style={S.row}>
            <div>
              <div style={S.label}>Name</div>
              <input value={cfg.name} onChange={e=>set('name',e.target.value)} style={S.field}/>
            </div>
            <div>
              <div style={S.label}>Platform</div>
              <select value={cfg.os} onChange={e=>{ set('os',e.target.value as OS); set('format',FORMATS_BY_OS[e.target.value as OS][0]); }} style={S.field}>
                {(['linux','windows','macos'] as OS[]).map(o=><option key={o}>{o}</option>)}
              </select>
            </div>
          </div>
          <div style={S.row}>
            <div>
              <div style={S.label}>Format</div>
              <select value={cfg.format} onChange={e=>set('format',e.target.value as Format)} style={S.field}>
                {formats.map(f=><option key={f}>{f}</option>)}
              </select>
            </div>
          </div>
        </div>

        {/* Callback */}
        <div style={S.section}>
          <div style={S.sectionTitle}>Callback / C2 Channel</div>
          <div style={S.row}>
            <div>
              <div style={S.label}>C2 Host</div>
              <input value={cfg.host} onChange={e=>set('host',e.target.value)} style={S.field}/>
            </div>
            <div>
              <div style={S.label}>Port</div>
              <input value={cfg.port} onChange={e=>set('port',e.target.value)} style={S.field}/>
            </div>
          </div>
          <div style={S.row}>
            <div>
              <div style={S.label}>Protocol</div>
              <select value={cfg.protocol} onChange={e=>set('protocol',e.target.value as Protocol)} style={S.field}>
                {(['http','https','dns','tcp','icmp'] as Protocol[]).map(p=><option key={p}>{p}</option>)}
              </select>
            </div>
            <div>
              <div style={S.label}>Sleep / Jitter (s / %)</div>
              <div style={{ display:'flex', gap:6 }}>
                <input value={cfg.interval} onChange={e=>set('interval',e.target.value)} style={{...S.field,width:60}}/>
                <input value={cfg.jitter}   onChange={e=>set('jitter',e.target.value)}   style={{...S.field,width:60}}/>
              </div>
            </div>
          </div>
          <div>
            <div style={S.label}>User-Agent</div>
            <input value={cfg.userAgent} onChange={e=>set('userAgent',e.target.value)} style={S.field}/>
          </div>
        </div>

        {/* Encoding */}
        <div style={S.section}>
          <div style={S.sectionTitle}>Encoding &amp; Obfuscation</div>
          <div style={S.row}>
            <div>
              <div style={S.label}>Encoding</div>
              <select value={cfg.encoding} onChange={e=>set('encoding',e.target.value as Encoding)} style={S.field}>
                {(['none','xor','aes-256','chacha20','rc4'] as Encoding[]).map(e=><option key={e}>{e}</option>)}
              </select>
            </div>
            <div>
              <div style={S.label}>Key (hex, empty=random)</div>
              <input value={cfg.key} onChange={e=>set('key',e.target.value)} placeholder="random" style={S.field}/>
            </div>
          </div>
        </div>

        {/* Injection */}
        <div style={S.section}>
          <div style={S.sectionTitle}>Process Injection</div>
          <div style={S.row}>
            <div>
              <div style={S.label}>Technique</div>
              <select value={cfg.inject} onChange={e=>set('inject',e.target.value as Inject)} style={S.field}>
                {(['self','remote','hollow','early-bird','module-stomp'] as Inject[]).map(i=><option key={i}>{i}</option>)}
              </select>
            </div>
            {cfg.inject !== 'self' && (
              <div>
                <div style={S.label}>PPID / Target Process</div>
                <input value={cfg.ppid} onChange={e=>set('ppid',e.target.value)} style={S.field}/>
              </div>
            )}
          </div>
        </div>

        {/* Persistence */}
        <div style={S.section}>
          <div style={S.sectionTitle}>Persistence</div>
          <div>
            <div style={S.label}>Mechanism</div>
            <select value={cfg.persist} onChange={e=>set('persist',e.target.value as PersistM)} style={S.field}>
              {(['none','registry-run','scheduled-task','cron','service','dll-hijack'] as PersistM[]).map(p=><option key={p}>{p}</option>)}
            </select>
          </div>
        </div>

        {/* Evasion toggles */}
        <div style={S.section}>
          <div style={S.sectionTitle}>Evasion &amp; Anti-Analysis</div>
          <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr', gap:8 }}>
            {([
              ['sandbox',  'Sandbox Evasion'],
              ['antiDebug','Anti-Debug'],
              ['sleepMask','Sleep Mask / Obf'],
              ['amsiPatch','AMSI Patch'],
            ] as [keyof ImplantConfig,string][]).map(([k,label])=>(
              <label key={k} style={S.checkbox} onClick={()=>set(k, !cfg[k] as ImplantConfig[typeof k])}>
                <div style={{ width:14, height:14, border:`1px solid ${cfg[k]?'#e05c6e':'#1a1a1a'}`, background:cfg[k]?'#1a0000':'transparent', display:'flex', alignItems:'center', justifyContent:'center', flexShrink:0 }}>
                  {cfg[k] && <span style={{ fontSize:9, color:'#e05c6e' }}>✓</span>}
                </div>
                <span style={{ fontSize:11, color:'var(--tx1)' }}>{label}</span>
              </label>
            ))}
          </div>
        </div>

        {/* Lifetime */}
        <div style={S.section}>
          <div style={S.sectionTitle}>Lifetime</div>
          <div style={S.row}>
            <div>
              <div style={S.label}>Kill Date</div>
              <input value={cfg.killDate} onChange={e=>set('killDate',e.target.value)} style={S.field}/>
            </div>
            <div>
              <div style={S.label}>Max Retries</div>
              <input value={cfg.maxRetries} onChange={e=>set('maxRetries',e.target.value)} style={S.field}/>
            </div>
          </div>
        </div>
      </div>

      {/* Right — summary + generate */}
      <div style={{ width:260, background:'var(--panel)', display:'flex', flexDirection:'column', flexShrink:0 }}>
        <div style={{ padding:'10px 12px', borderBottom:'1px solid var(--b1)', fontSize:9, color:'var(--tx2)', textTransform:'uppercase', letterSpacing:1 }}>Summary</div>

        <div style={{ flex:1, overflowY:'auto', padding:'10px 12px' }}>
          {([
            ['Output',    summary],
            ['Platform',  cfg.os],
            ['Format',    cfg.format],
            ['Protocol',  cfg.protocol + (cfg.https?'+TLS':'')],
            ['C2',        `${cfg.host}:${cfg.port}`],
            ['Sleep',     `${cfg.interval}s ± ${cfg.jitter}%`],
            ['Encoding',  cfg.encoding],
            ['Injection', cfg.inject],
            ['Persist',   cfg.persist],
            ['Kill date', cfg.killDate],
          ] as [string,string][]).map(([k,v])=>(
            <div key={k} style={{ display:'flex', justifyContent:'space-between', marginBottom:6, fontSize:10 }}>
              <span style={{ color:'var(--tx2)' }}>{k}</span>
              <span style={{ color:'var(--tx1)' }}>{v}</span>
            </div>
          ))}

          <div style={{ marginTop:8, display:'flex', gap:6, flexWrap:'wrap' }}>
            {cfg.sandbox   && <span style={{ fontSize:8, padding:'2px 6px', border:'1px solid #1a1a1a', color:'var(--tx1)' }}>SANDBOX-EVADE</span>}
            {cfg.antiDebug && <span style={{ fontSize:8, padding:'2px 6px', border:'1px solid var(--b2)', color:'var(--tx1)' }}>ANTI-DEBUG</span>}
            {cfg.sleepMask && <span style={{ fontSize:8, padding:'2px 6px', border:'1px solid var(--b2)', color:'var(--tx1)' }}>SLEEP-MASK</span>}
            {cfg.amsiPatch && <span style={{ fontSize:8, padding:'2px 6px', border:'1px solid var(--b2)', color:'var(--tx1)' }}>AMSI-PATCH</span>}
          </div>

          {generated && (
            <div style={{ marginTop:16, padding:'10px', background:'var(--inset2)', border:'1px solid #1a2a1a' }}>
              <div style={{ fontSize:10, color:'#33a84a', marginBottom:4 }}>[+] Implant generated</div>
              <div style={{ fontSize:10, color:'var(--tx1)' }}>{summary}</div>
              <div style={{ fontSize:10, color:'var(--tx2)', marginTop:2 }}>MD5: 8f4e2a…c1d3</div>
              <div style={{ fontSize:10, color:'var(--tx2)' }}>Size: 124 KB</div>
              <div style={{ display:'flex', gap:6, marginTop:8 }}>
                <button style={{ flex:1, background:'var(--inset2)', border:'1px solid #1a2a1a', color:'#33a84a', fontFamily:'Courier New', fontSize:9, padding:'4px', cursor:'pointer' }}>DOWNLOAD</button>
                <button style={{ flex:1, background:'var(--inset2)', border:'1px solid #1a1a1a', color:'#5a96d4', fontFamily:'Courier New', fontSize:9, padding:'4px', cursor:'pointer' }}>STAGE</button>
              </div>
            </div>
          )}
        </div>

        <div style={{ padding:'10px 12px', borderTop:'1px solid #1a1a1a', flexShrink:0 }}>
          <button onClick={generate} disabled={generating} style={{
            width:'100%', background: generating?'#0d0d0d':'#1a0000',
            border:`1px solid ${generating?'#222':'#e05c6e'}`,
            color: generating?'var(--tx2)':'#e05c6e',
            fontFamily:'Courier New', fontSize:12, fontWeight:700,
            padding:'8px', cursor: generating?'default':'pointer', letterSpacing:1,
          }}>
            {generating?'[ GENERATING... ]':'[ GENERATE IMPLANT ]'}
          </button>
          <div style={{ fontSize:9, color:'var(--tx3)', textAlign:'center', marginTop:4 }}>
            Tauri invoke → Arsenal C++ builder
          </div>
        </div>
      </div>
    </div>
  );
}
