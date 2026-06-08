import { useState, useEffect } from 'react';
import { auth } from '@/lib/client/api';

interface BootLine { text: string; color: string; }

const BOOT: BootLine[] = [
  { text: '[*] Initializing ZK C2 Framework v3.0.1...', color: '#444' },
  { text: '[*] Loading Spring Boot context...',          color: '#444' },
  { text: '[+] Database connected: c2_db',              color: '#33a84a' },
  { text: '[+] Spring Security — JWT + JSESSIONID',     color: '#33a84a' },
  { text: '[+] Listener active: 0.0.0.0:4444/tcp',      color: '#33a84a' },
  { text: '[*] Awaiting operator credentials...',       color: '#444' },
];

interface Props { onLogin: () => void; }

export default function LoginPage({ onLogin }: Props) {
  const [user,    setUser]    = useState('');
  const [pass,    setPass]    = useState('');
  const [error,   setError]   = useState('');
  const [loading, setLoading] = useState(false);
  const [lines,   setLines]   = useState<BootLine[]>([]);
  const [time,    setTime]    = useState('');

  useEffect(() => {
    let i = 0;
    const id = setInterval(() => {
      if (i < BOOT.length) { setLines(p => [...p, BOOT[i]]); i++; }
      else clearInterval(id);
    }, 300);
    return () => clearInterval(id);
  }, []);

  useEffect(() => {
    const tick = () => {
      const n = new Date();
      setTime(`${n.getUTCHours().toString().padStart(2,'0')}:${n.getUTCMinutes().toString().padStart(2,'0')}:${n.getUTCSeconds().toString().padStart(2,'0')} UTC`);
    };
    tick();
    const id = setInterval(tick, 1000);
    return () => clearInterval(id);
  }, []);

  const handleLogin = async () => {
    if (!user || !pass) { setError('[-] Error: credentials required'); return; }
    setLoading(true);
    setError('');
    try {
      await auth.login(user, pass);
      onLogin();
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : 'unknown error';
      setError(`[-] Error: ${msg.includes('401') || msg.toLowerCase().includes('unauthorized') ? 'invalid credentials — access denied' : msg}`);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{ height:'100vh', background:'#080808', display:'flex', alignItems:'center', justifyContent:'center', fontFamily:'Courier New' }}>
      <div style={{ display:'flex', width:'100%', maxWidth:920, height:540 }}>

        {/* LEFT */}
        <div style={{ width:420, background:'#0d0d0d', border:'1px solid #1a1a1a', borderRight:'none', display:'flex', flexDirection:'column' }}>
          <div style={{ background:'#080808', borderBottom:'1px solid #1a1a1a', padding:'5px 20px', display:'flex', justifyContent:'space-between', fontSize:10 }}>
            <span style={{ color:'#222' }}>C2 INFRASTRUCTURE</span>
            <span style={{ color:'#e05c6e' }}>SECURE CHANNEL</span>
          </div>

          <div style={{ flex:1, padding:'22px 26px', display:'flex', flexDirection:'column' }}>
            <div style={{ textAlign:'center', marginBottom:20 }}>
              <div style={{ width:52, height:52, border:'1px solid rgba(224,92,110,0.3)', background:'rgba(224,92,110,0.05)', display:'flex', alignItems:'center', justifyContent:'center', margin:'0 auto 10px', fontSize:22 }}>☣</div>
              <div style={{ fontSize:16, fontWeight:700, color:'#cccccc', letterSpacing:1 }}>ZOMBIE KEEPER</div>
              <div style={{ fontSize:10, color:'#e05c6e', marginTop:3 }}>C2 Framework v3.0.1</div>
            </div>

            {error && (
              <div style={{ marginBottom:12, padding:'7px 10px', background:'rgba(224,92,110,0.08)', border:'1px solid #e05c6e', fontSize:11, color:'#e05c6e' }}>
                {error}
              </div>
            )}

            <div style={{ background:'#080808', border:'1px solid #1a1a1a', padding:'14px', marginBottom:14 }}>
              <div style={{ fontSize:9, color:'#333', letterSpacing:'1px', marginBottom:5, textTransform:'uppercase' }}>User</div>
              <input style={{ width:'100%', background:'#050505', border:'1px solid #1a1a1a', color:'#cccccc', fontFamily:'Courier New', fontSize:12, padding:'6px 8px', outline:'none', marginBottom:12, boxSizing:'border-box' as const }}
                placeholder="username" value={user} onChange={e=>setUser(e.target.value)}
                onKeyDown={e=>e.key==='Enter'&&handleLogin()} disabled={loading} />
              <div style={{ fontSize:9, color:'#333', letterSpacing:'1px', marginBottom:5, textTransform:'uppercase' }}>Password</div>
              <input type="password" style={{ width:'100%', background:'#050505', border:'1px solid #1a1a1a', color:'#cccccc', fontFamily:'Courier New', fontSize:12, padding:'6px 8px', outline:'none', boxSizing:'border-box' as const }}
                placeholder="••••••••" value={pass} onChange={e=>setPass(e.target.value)}
                onKeyDown={e=>e.key==='Enter'&&handleLogin()} disabled={loading} />
            </div>

            <button onClick={handleLogin} disabled={loading}
              style={{ width:'100%', background:'#1a0000', border:'1px solid #e05c6e', color: loading ? '#444' : '#e05c6e', fontFamily:'Courier New', fontSize:12, fontWeight:700, padding:'9px', cursor: loading ? 'not-allowed' : 'pointer', letterSpacing:1, textTransform:'uppercase', marginBottom:14 }}>
              {loading ? '[*] AUTHENTICATING...' : '> INITIALIZE SWARM UPLINK'}
            </button>

            <div style={{ flex:1, background:'#060606', border:'1px solid #111', overflow:'hidden', display:'flex', flexDirection:'column' }}>
              <div style={{ display:'flex', justifyContent:'space-between', alignItems:'center', padding:'4px 10px', background:'#0a0a0a', borderBottom:'1px solid #111' }}>
                <div style={{ display:'flex', gap:5 }}>
                  <div style={{ width:7, height:7, borderRadius:'50%', background:'rgba(224,92,110,0.5)' }}/>
                  <div style={{ width:7, height:7, borderRadius:'50%', background:'#1a1a1a' }}/>
                </div>
                <span style={{ fontSize:9, color:'#222', letterSpacing:1 }}>SESSION LOGS</span>
              </div>
              <div style={{ padding:'8px 10px', flex:1, overflowY:'auto' as const }}>
                {lines.map((l, i) => (
                  <div key={i} style={{ fontSize:10, lineHeight:1.7, color: l?.color || '#444' }}>{l?.text || ''}</div>
                ))}
              </div>
            </div>
          </div>
        </div>

        {/* RIGHT */}
        <div style={{ flex:1, background:'#060606', border:'1px solid #1a1a1a', display:'flex', flexDirection:'column', alignItems:'center', justifyContent:'center', position:'relative' as const }}>
          <div style={{ position:'absolute', left:0, top:'20%', bottom:'20%', width:1, background:'linear-gradient(to bottom, transparent, #1a1a1a, transparent)' }}/>
          <div style={{ textAlign:'center', maxWidth:300 }}>
            <div style={{ fontSize:26, color:'#e05c6e', marginBottom:26 }}>☣</div>
            <div style={{ fontSize:13, color:'#1a1a1a', fontStyle:'italic', lineHeight:1.9 }}>The puppeteer is</div>
            <div style={{ fontSize:13, color:'#e05c6e', fontStyle:'italic' }}>invisible.</div>
            <div style={{ height:10 }}/>
            <div style={{ fontSize:13, color:'#1a1a1a', fontStyle:'italic', lineHeight:1.9 }}>The puppet believes it</div>
            <div style={{ fontSize:13, color:'#e05c6e', fontStyle:'italic' }}>dances alone.</div>
            <div style={{ width:28, height:1, background:'rgba(224,92,110,0.2)', margin:'16px auto' }}/>
            <div style={{ fontSize:9, color:'#1a1a1a', letterSpacing:2 }}>ZOMBIE KEEPER — C2 FRAMEWORK</div>
          </div>
          <div style={{ position:'absolute', bottom:12, fontSize:9, color:'#111', letterSpacing:1 }}>AUTHORIZED ACCESS ONLY</div>
          <div style={{ position:'absolute', top:10, right:12, fontSize:10, color:'#1a1a1a' }}>{time}</div>
        </div>
      </div>
    </div>
  );
}
