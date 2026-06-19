import { useState } from 'react';

// ── Options ──────────────────────────────────────────────────────────────────
const TARGET_OS    = ['Windows x64','Windows x86','Windows ARM64','Linux x64','Linux x86','Linux ARM','Linux MIPS','macOS ARM64 (M1/M2)','macOS x64 (Intel)','FreeBSD x64','Android','iOS (jailbreak)'];
const FORMATS      = ['EXE (.exe)','DLL (.dll)','PowerShell (.ps1)','Shellcode (raw)','Shellcode (base64)','ELF (.elf)','Shared Object (.so)','Mach-O','Python (.py)','Perl (.pl)','Bash Script (.sh)','HTA (.hta)','VBA Macro','LNK Shortcut','ISO Image','Office Macro (docm)'];
const LISTENERS    = ['HTTP — 0.0.0.0:4444','HTTPS — 0.0.0.0:8443','DNS — 0.0.0.0:53','SMB Named Pipe','TCP Bind — 0.0.0.0:5555','TCP Reverse — 0.0.0.0:4445'];
const ENCODINGS    = ['None','Base64','XOR (single-byte)','XOR (multi-byte)','AES-128-CBC','AES-256-CBC','ChaCha20','RC4','Custom XOR key'];
const ARCHITECTURES= ['x86_64','x86 (32-bit)','ARM64','ARM (32-bit)','MIPS'];
const SPAWN_TO     = ['%WINDIR%\\System32\\svchost.exe','%WINDIR%\\System32\\notepad.exe','%WINDIR%\\System32\\rundll32.exe','%WINDIR%\\SysWOW64\\svchost.exe','Custom path...'];
const COMMS_PROTO  = ['HTTP/1.1','HTTP/2','HTTPS/TLS 1.2','HTTPS/TLS 1.3','DNS-over-HTTPS','WebSocket','gRPC'];
const INJECT_TYPES = ['None','Process Hollowing','Thread Hijacking','APC Injection','Early Bird APC','DLL Injection','Reflective DLL','PPID Spoofing','Heaven\'s Gate (32→64)','NtCreateSection Map','Thread Pool Hijacking','Module Stomping','Ghost Writing','NtCreateThreadEx (direct syscall)'];
const SANDBOX_EVADE= ['None','Sleep check (> 60s)','User interaction check','CPU core count check','RAM check (> 2GB)','Domain join check','Screensaver check','Mouse movement check','Registry artifact check','Network adapter check','Process list check (VM/AV procs)','Time acceleration check','Loaded DLL check (EDR/AV)','Disk size check (> 60 GB)'];
const OBFUSCATIONS = ['None','String encryption','Import table obfuscation','Control flow flattening','Anti-debug','Anti-VM','Stack strings','All (heavy)'];
const ANTI_ANALYSIS= ['None','ETW patching','AMSI bypass (patch amsi.dll)','Unhook ntdll.dll (fresh disk copy)','Hook detection + kill on detect','ETW + AMSI combined','Full stealth (all techniques)'];
const PERSISTENCE  = ['None','Registry Run key (HKCU)','Registry Run key (HKLM)','Scheduled Task via COM (ITaskService)','WMI event subscription','Startup folder LNK','Windows Service install','DLL hijacking (system path)','IFEO debugger key'];

const LOG_LINES_BASE = [
  '[*] Initializing payload builder...',
  '[*] Loading base template...',
  '[+] Template loaded successfully',
  '[*] Applying configuration...',
  '[*] Encoding payload...',
  '[*] Applying evasion techniques...',
  '[*] Running OPSEC checks...',
  '[*] Stripping debug symbols...',
  '[*] Packing binary...',
  '[*] Generating staging URL...',
  '[+] Build complete.',
];

interface Config {
  os: string; arch: string; format: string; listener: string;
  encoding: string; comms: string; spawnTo: string; inject: string;
  sandbox: string; obfusc: string; sleep: string; jitter: string;
  killdate: string; userAgent: string; proxy: string; maxRetry: string;
  callbackHosts: string; referer: string; x64: boolean; stageless: boolean;
  https_verify: boolean; prepend_null: boolean;
  anti_analysis: string; persistence: string; ppid_target: string;
}

const DEFAULT: Config = {
  os:'Windows x64', arch:'x86_64', format:'EXE (.exe)', listener:'HTTP — 0.0.0.0:4444',
  encoding:'None', comms:'HTTP/1.1', spawnTo:'%WINDIR%\\System32\\svchost.exe',
  inject:'None', sandbox:'None', obfusc:'None',
  sleep:'10', jitter:'23', killdate:'', userAgent:'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
  proxy:'', maxRetry:'5', callbackHosts:'', referer:'', x64:true, stageless:false,
  https_verify:true, prepend_null:false,
  anti_analysis:'None', persistence:'None', ppid_target:'%WINDIR%\\System32\\explorer.exe',
};

const S = {
  lbl: { fontSize:9, color:'#444', textTransform:'uppercase' as const, letterSpacing:'1px', marginBottom:5, display:'block' as const },
  field: { width:'100%', background:'#040404', border:'1px solid #1e1e1e', color:'#cccccc', fontFamily:'Courier New', fontSize:12, padding:'6px 8px', outline:'none' as const, appearance:'none' as const },
  row: { marginBottom:12 },
  sec: { fontSize:9, color:'#333', textTransform:'uppercase' as const, letterSpacing:'1.2px', padding:'8px 0 4px', display:'block' as const, borderBottom:'1px solid #111', marginBottom:10 },
};

function Toggle({ label, desc, value, onChange }: { label:string; desc:string; value:boolean; onChange:(v:boolean)=>void }) {
  return (
    <div style={{ display:'flex', alignItems:'center', justifyContent:'space-between', marginBottom:10 }}>
      <div>
        <div style={{ fontSize:11, color:'#888', fontFamily:'Courier New' }}>{label}</div>
        <div style={{ fontSize:9, color:'#333', fontFamily:'Courier New', marginTop:1 }}>{desc}</div>
      </div>
      <button onClick={()=>onChange(!value)} style={{ background:value?'#1a0000':'#0d0d0d', border:`1px solid ${value?'#e05c6e':'#222'}`, color:value?'#e05c6e':'#444', fontFamily:'Courier New', fontSize:9, fontWeight:700, padding:'3px 10px', cursor:'pointer', minWidth:40 }}>
        {value?'ON':'OFF'}
      </button>
    </div>
  );
}

function Select({ label, value, options, onChange }: { label:string; value:string; options:string[]; onChange:(v:string)=>void }) {
  return (
    <div style={S.row}>
      <span style={S.lbl}>{label}</span>
      <select value={value} onChange={e=>onChange(e.target.value)} style={S.field}>
        {options.map(o=><option key={o}>{o}</option>)}
      </select>
    </div>
  );
}

function Input({ label, value, onChange, placeholder }: { label:string; value:string; onChange:(v:string)=>void; placeholder?:string }) {
  return (
    <div style={S.row}>
      <span style={S.lbl}>{label}</span>
      <input value={value} onChange={e=>onChange(e.target.value)} placeholder={placeholder||''} style={S.field}/>
    </div>
  );
}

export default function PayloadGenerator() {
  const [cfg,     setCfg]    = useState<Config>(DEFAULT);
  const [built,   setBuilt]  = useState(false);
  const [building,setBuild]  = useState(false);
  const [buildLog,setLog]    = useState<string[]>([]);
  const [tab,     setTab]    = useState<'basic'|'evasion'|'network'|'advanced'>('basic');

  const set = (k: keyof Config) => (v: string | boolean) => setCfg(p => ({...p, [k]:v}));

  const generate = () => {
    setBuild(true); setBuilt(false); setLog([]);
    LOG_LINES_BASE.forEach((line,i) => {
      setTimeout(()=>{
        setLog(p=>[...p, line]);
        if(i===LOG_LINES_BASE.length-1){ setTimeout(()=>{ setBuild(false); setBuilt(true); }, 300); }
      }, i * 160);
    });
  };

  const TABS = ['basic','evasion','network','advanced'] as const;

  return (
    <div style={{ display:'flex', height:'100%', overflow:'hidden' }}>

      {/* ── CONFIG PANEL ── */}
      <div style={{ width:340, background:'#0d0d0d', borderRight:'1px solid #1a1a1a', display:'flex', flexDirection:'column', overflow:'hidden', flexShrink:0 }}>

        {/* Tab bar */}
        <div style={{ display:'flex', background:'#080808', borderBottom:'1px solid #1a1a1a', flexShrink:0 }}>
          {TABS.map(t=>(
            <div key={t} onClick={()=>setTab(t)} style={{
              flex:1, padding:'6px 0', textAlign:'center', fontSize:9, fontFamily:'Courier New',
              textTransform:'uppercase', letterSpacing:'0.8px', cursor:'pointer',
              color: tab===t?'#cccccc':'#333',
              borderTop: tab===t?'2px solid #e05c6e':'2px solid transparent',
              background: tab===t?'#0d0d0d':'transparent',
            }}>{t}</div>
          ))}
        </div>

        <div style={{ flex:1, overflowY:'auto', padding:'14px 14px 0' }}>

          {tab === 'basic' && <>
            <span style={S.sec}>Target</span>
            <Select label="Operating System" value={cfg.os}     options={TARGET_OS}      onChange={set('os')} />
            <Select label="Architecture"     value={cfg.arch}   options={ARCHITECTURES}  onChange={set('arch')} />
            <Select label="Output Format"    value={cfg.format} options={FORMATS}         onChange={set('format')} />
            <span style={S.sec}>C2 Connection</span>
            <Select label="Listener"         value={cfg.listener}  options={LISTENERS}   onChange={set('listener')} />
            <Input  label="Additional Callback Hosts (comma-sep)" value={cfg.callbackHosts} onChange={set('callbackHosts')} placeholder="backup.domain.com, cdn.example.com" />
            <Select label="Comms Protocol"   value={cfg.comms}     options={COMMS_PROTO} onChange={set('comms')} />
            <span style={S.sec}>Timing</span>
            <div style={{ display:'flex', gap:10, marginBottom:12 }}>
              <div style={{ flex:1 }}><Input label="Sleep (seconds)"  value={cfg.sleep}  onChange={set('sleep')} /></div>
              <div style={{ flex:1 }}><Input label="Jitter (%)"       value={cfg.jitter} onChange={set('jitter')} /></div>
            </div>
            <div style={{ display:'flex', gap:10, marginBottom:12 }}>
              <div style={{ flex:1 }}><Input label="Max Retry Attempts" value={cfg.maxRetry} onChange={set('maxRetry')} /></div>
              <div style={{ flex:1 }}><Input label="Kill Date (YYYY-MM-DD)" value={cfg.killdate} onChange={set('killdate')} placeholder="2027-12-31" /></div>
            </div>
            <Toggle label="Stageless payload"   desc="Embed full agent — no staging request"         value={cfg.stageless}    onChange={set('stageless')} />
            <Toggle label="x64 shellcode stub"  desc="Force x64 shellcode header"                    value={cfg.x64}          onChange={set('x64')} />
          </>}

          {tab === 'evasion' && <>
            <span style={S.sec}>Encoding & Obfuscation</span>
            <Select label="Payload Encoding"    value={cfg.encoding} options={ENCODINGS}        onChange={set('encoding')} />
            <Select label="Code Obfuscation"    value={cfg.obfusc}   options={OBFUSCATIONS}     onChange={set('obfusc')} />
            <Toggle label="Prepend null bytes"  desc="Prepend 0x00 bytes to evade signature"    value={cfg.prepend_null} onChange={set('prepend_null')} />
            <span style={S.sec}>Process Injection</span>
            <Select label="Injection Technique" value={cfg.inject}   options={INJECT_TYPES}     onChange={set('inject')} />
            <Select label="Spawn-To Process"    value={cfg.spawnTo}  options={SPAWN_TO}         onChange={set('spawnTo')} />
            {cfg.inject === 'PPID Spoofing' && (
              <Input label="PPID Target Process" value={cfg.ppid_target} onChange={set('ppid_target')} placeholder="%WINDIR%\System32\explorer.exe" />
            )}
            <span style={S.sec}>Anti-Analysis</span>
            <Select label="EDR/AV Bypass"       value={cfg.anti_analysis} options={ANTI_ANALYSIS} onChange={set('anti_analysis')} />
            <span style={S.sec}>Sandbox Evasion</span>
            <Select label="Sandbox Check"       value={cfg.sandbox}  options={SANDBOX_EVADE}    onChange={set('sandbox')} />
            <span style={S.sec}>Persistence</span>
            <Select label="Persistence Method"  value={cfg.persistence} options={PERSISTENCE}   onChange={set('persistence')} />
          </>}

          {tab === 'network' && (()=>{
            const listenerHost = cfg.listener.replace(/^[A-Z0-9/. ]+ — /,'');
            const ua = cfg.userAgent;
            return <>
              <span style={S.sec}>HTTP Headers</span>
              <Input label="User-Agent"             value={cfg.userAgent} onChange={set('userAgent')} />
              <Input label="Referer"                value={cfg.referer}   onChange={set('referer')}   placeholder="https://www.google.com" />
              <Input label="HTTP Proxy (host:port)" value={cfg.proxy}     onChange={set('proxy')}     placeholder="proxy.corp.local:8080" />
              <span style={S.sec}>Beacon URI</span>
              <Input label="Check-in Path"          value={cfg.callbackHosts} onChange={set('callbackHosts')} placeholder="/jquery-3.5.1.min.js, /api/data" />
              <span style={S.sec}>TLS / SSL</span>
              <Toggle label="Verify HTTPS cert"   desc="Validate server TLS certificate"         value={cfg.https_verify} onChange={set('https_verify')} />
              <span style={S.sec}>Preview — Generated Headers</span>
              <div style={{ background:'#080808', border:'1px solid #1a1a1a', padding:'8px 10px', fontFamily:'Courier New', fontSize:10, color:'#555', marginBottom:12, lineHeight:1.6 }}>
                <div style={{color:'#444'}}>GET /beacon HTTP/1.1</div>
                <div><span style={{color:'#3a3a3a'}}>Host: </span>{listenerHost}</div>
                <div><span style={{color:'#3a3a3a'}}>User-Agent: </span>{ua.length > 50 ? ua.slice(0,50)+'…' : ua}</div>
                {cfg.referer && <div><span style={{color:'#3a3a3a'}}>Referer: </span>{cfg.referer}</div>}
                {cfg.proxy   && <div><span style={{color:'#3a3a3a'}}>X-Forwarded-For: </span>{cfg.proxy}</div>}
                <div><span style={{color:'#3a3a3a'}}>Accept: </span>*/*</div>
                <div><span style={{color:'#3a3a3a'}}>Connection: </span>keep-alive</div>
              </div>
            </>;
          })()}

          {tab === 'advanced' && <>
            <span style={S.sec}>Build Options</span>
            <div style={{ marginBottom:12, padding:'10px', background:'#080808', border:'1px solid #1a1a1a' }}>
              <div style={{ fontSize:10, color:'#555', fontFamily:'Courier New', lineHeight:1.7 }}>
                <div><span style={{ color:'#444' }}>OS:</span>       {cfg.os}</div>
                <div><span style={{ color:'#444' }}>Arch:</span>     {cfg.arch}</div>
                <div><span style={{ color:'#444' }}>Format:</span>   {cfg.format}</div>
                <div><span style={{ color:'#444' }}>Listener:</span> {cfg.listener}</div>
                <div><span style={{ color:'#444' }}>Encoding:</span> {cfg.encoding}</div>
                <div><span style={{ color:'#444' }}>Inject:</span>      {cfg.inject}</div>
                <div><span style={{ color:'#444' }}>Anti-Analysis:</span>{cfg.anti_analysis}</div>
                <div><span style={{ color:'#444' }}>Sandbox:</span>     {cfg.sandbox}</div>
                <div><span style={{ color:'#444' }}>Persistence:</span> {cfg.persistence}</div>
                <div><span style={{ color:'#444' }}>Sleep:</span>       {cfg.sleep}s / {cfg.jitter}% jitter</div>
                <div><span style={{ color:'#444' }}>Kill Date:</span>   {cfg.killdate || 'none'}</div>
                <div><span style={{ color:'#444' }}>Stageless:</span>   {cfg.stageless?'yes':'no'}</div>
              </div>
            </div>
            <span style={S.sec}>Raw Builder Command</span>
            <div style={{ background:'#080808', border:'1px solid #1a1a1a', padding:'8px 10px', fontFamily:'Courier New', fontSize:10, color:'#444', wordBreak:'break-all', marginBottom:12 }}>
              {'zk-build'} --os "{cfg.os}" --arch "{cfg.arch}" --fmt "{cfg.format}" --listener "{cfg.listener}" --enc "{cfg.encoding}" --inject "{cfg.inject}" --anti "{cfg.anti_analysis}" --sandbox "{cfg.sandbox}" --persist "{cfg.persistence}" --sleep {cfg.sleep} --jitter {cfg.jitter}{cfg.stageless?' --stageless':''}{cfg.killdate?` --killdate "${cfg.killdate}"`:''}
            </div>
            <span style={S.sec}>API Endpoint</span>
            <div style={{ background:'#080808', border:'1px solid #1a1a1a', padding:'8px 10px', fontFamily:'Courier New', fontSize:10, color:'#444', marginBottom:12 }}>
              POST /api/payload/build<br/>
              Content-Type: application/json<br/>
              Authorization: Bearer {'<JWT>'}
            </div>
          </>}
        </div>

        {/* Generate button */}
        <div style={{ padding:'12px 14px', borderTop:'1px solid #1a1a1a', flexShrink:0 }}>
          <button onClick={generate} disabled={building} style={{
            width:'100%', background:building?'#0d0d0d':'#1a0000',
            border:`1px solid ${building?'#222':'#e05c6e'}`,
            color:building?'#333':'#e05c6e', fontFamily:'Courier New',
            fontSize:12, fontWeight:700, padding:'10px', cursor:building?'default':'pointer', letterSpacing:1,
          }}>
            {building ? '[ BUILDING... ]' : '[ GENERATE PAYLOAD ]'}
          </button>
        </div>
      </div>

      {/* ── BUILD OUTPUT ── */}
      <div style={{ flex:1, display:'flex', flexDirection:'column', background:'#080808', overflow:'hidden' }}>
        <div style={{ padding:'5px 12px', background:'#111', borderBottom:'1px solid #1a1a1a', fontSize:10, color:'#444', textTransform:'uppercase', letterSpacing:1, flexShrink:0, display:'flex', alignItems:'center', gap:10 }}>
          <span>Build Output</span>
          {building && <span style={{ color:'#d48b55' }}>● BUILDING</span>}
          {built && !building && <span style={{ color:'#33a84a' }}>● SUCCESS</span>}
        </div>
        <div style={{ flex:1, overflowY:'auto', padding:'14px', fontFamily:'Courier New', fontSize:12 }}>
          {buildLog.length === 0 && !built && (
            <div style={{ color:'#222' }}>[*] Configure payload and click Generate</div>
          )}
          {buildLog.map((l,i) => (
            <div key={i} style={{ color:l.startsWith('[+')?'#33a84a':l.startsWith('[*')?'#555':'#888', marginBottom:3, lineHeight:1.5 }}>{l}</div>
          ))}
          {built && !building && (
            <div style={{ marginTop:16 }}>
              <div style={{ color:'#33a84a', marginBottom:12, fontSize:13, fontWeight:700 }}>[+] Payload built successfully</div>
              <div style={{ background:'#0d0d0d', border:'1px solid #1a1a1a', padding:'12px', marginBottom:14 }}>
                {[
                  ['Target OS', cfg.os], ['Architecture', cfg.arch], ['Format', cfg.format],
                  ['Listener', cfg.listener], ['Encoding', cfg.encoding],
                  ['Injection', cfg.inject], ['Obfuscation', cfg.obfusc],
                  ['Sandbox Check', cfg.sandbox], ['Sleep / Jitter', `${cfg.sleep}s / ${cfg.jitter}%`],
                  ['Stageless', cfg.stageless?'yes':'no'], ['Size', '47.2 KB'],
                  ['SHA256', 'a3f4e2d1...c9b8a7f6'], ['MD5', 'd9c1b8a7...f6e5d4c3'],
                  ['Output', `/tmp/zk_payload_${Date.now()}.${cfg.format.split('(')[1]?.replace(')','').replace('.','').toLowerCase()||'bin'}`],
                ].map(([k,v])=>(
                  <div key={k} style={{ display:'flex', gap:12, marginBottom:4 }}>
                    <span style={{ color:'#444', minWidth:110 }}>{k}:</span>
                    <span style={{ color: k==='SHA256'||k==='MD5'?'#5bb8d4':'#777' }}>{v}</span>
                  </div>
                ))}
              </div>
              <div style={{ display:'flex', gap:8, flexWrap:'wrap' }}>
                {[['Download Binary','#e05c6e'],['Copy Base64','#777'],['Get Stage URL','#777'],['One-liner (PS)','#777'],['One-liner (curl)','#777']].map(([label,col])=>(
                  <button key={label} style={{ background:'#0d0d0d', border:`1px solid ${col==='#e05c6e'?'#e05c6e':'#222'}`, color:col, fontFamily:'Courier New', fontSize:11, padding:'5px 14px', cursor:'pointer' }}>{label}</button>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
