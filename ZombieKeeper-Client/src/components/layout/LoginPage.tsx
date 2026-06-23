import { useState, useEffect } from 'react';
import { auth } from '@/lib/client/api';

interface BootLine { label: string; flag: string; }

const BOOT: BootLine[] = [
  { label: 'ZK C2 FRAMEWORK v3.0.1',          flag: 'READY'  },
  { label: 'control program AUTH360',          flag: 'LOADED' },
  { label: 'db c2_db',                         flag: 'CONN'   },
  { label: 'spring-security · JWT+JSESSIONID', flag: 'OK'     },
  { label: 'listener 0.0.0.0:4444/tcp',        flag: 'ACTIVE' },
  { label: 'awaiting operator credentials',    flag: ''       },
];

const BARS = Array.from({ length: 38 }, (_, i) => i);

interface Props { onLogin: () => void; }

const CSS = `
@keyframes zkRoll    { from { opacity:0; transform:translateY(12px) } to { opacity:1; transform:translateY(0) } }
@keyframes zkFlicker { 0%,100%{opacity:.03} 7%{opacity:.09} 9%{opacity:.02} 50%{opacity:.055} 92%{opacity:.10} }
@keyframes zkWave    { 0%,100%{transform:scaleY(.16)} 50%{transform:scaleY(1)} }
@keyframes zkSweep   { from{left:-3%} to{left:103%} }
@keyframes zkLed     { 50%{opacity:.4} }
@keyframes zkBlink   { 0%,100%{opacity:1} 50%{opacity:0} }
@keyframes zkShake   { 0%,100%{transform:translateX(0)} 20%{transform:translateX(-4px)} 40%{transform:translateX(4px)} 60%{transform:translateX(-2px)} 80%{transform:translateX(2px)} }

.zk-lg-rivet   { position:absolute; width:7px; height:7px; border-radius:50%;
  background:radial-gradient(circle at 35% 35%, #5a5a5a, #141414);
  box-shadow:inset 0 1px 1px rgba(0,0,0,.85), 0 1px 0 rgba(255,255,255,.04); z-index:7; }
.zk-lg-well    { position:relative; background:var(--inset2); border:1px solid var(--b2);
  box-shadow:inset 0 2px 5px rgba(0,0,0,.6); display:flex; align-items:center; transition:all .14s; }
.zk-lg-well:focus-within { border-color:var(--red);
  box-shadow:inset 0 2px 5px rgba(0,0,0,.6), 0 0 12px rgba(204,68,68,.30); }
.zk-lg-plate   { position:absolute; top:-7px; left:12px; padding:0 6px; background:var(--panel);
  font-size:9px; letter-spacing:1.5px; color:var(--tx2); text-shadow:0 1px 0 #000; text-transform:uppercase; }
.zk-lg-well:focus-within .zk-lg-plate { color:var(--red-hi); }
.zk-lg-input   { flex:1; background:transparent; border:none; outline:none; color:var(--tx0);
  font-family:var(--mono); font-size:13px; padding:12px 12px; letter-spacing:.6px; min-width:0; }
.zk-lg-input::placeholder { color:var(--tx3); }
.zk-lg-led     { width:7px; height:7px; border-radius:50%; margin:0 12px; flex-shrink:0;
  background:var(--tx3); transition:all .14s; }
.zk-lg-well:focus-within .zk-lg-led { background:var(--red-hi); box-shadow:0 0 8px var(--red-hi); }

.zk-lg-btn     { width:100%; font-family:var(--mono); font-size:12px; font-weight:700; letter-spacing:2px;
  text-transform:uppercase; color:var(--red-hi); cursor:pointer; padding:12px; text-align:center;
  border:1px solid var(--red); border-radius:2px;
  background:linear-gradient(180deg, #43202a 0%, var(--red2) 55%, var(--red3) 100%);
  box-shadow:inset 0 1px 0 rgba(224,92,110,.25), inset 0 -2px 4px rgba(0,0,0,.5), 0 0 16px rgba(204,68,68,.10);
  transition:all .12s; }
.zk-lg-btn:hover:not(:disabled)  { color:#fff; border-color:var(--red-hi);
  box-shadow:inset 0 1px 0 rgba(224,92,110,.4), inset 0 -2px 4px rgba(0,0,0,.5), 0 0 22px rgba(204,68,68,.28); }
.zk-lg-btn:active:not(:disabled) { transform:translateY(1px);
  box-shadow:inset 0 2px 5px rgba(0,0,0,.6); }
.zk-lg-btn:disabled { color:var(--tx2); border-color:var(--b2); cursor:not-allowed;
  background:var(--inset2); box-shadow:inset 0 1px 0 rgba(255,255,255,.02); }

.zk-lg-scan    { position:absolute; inset:0; z-index:6; pointer-events:none; border-radius:3px;
  background:repeating-linear-gradient(0deg, rgba(0,0,0,.26) 0px, rgba(0,0,0,.26) 1px, transparent 1px, transparent 3px); }
.zk-lg-flicker { position:absolute; inset:0; z-index:6; pointer-events:none; border-radius:3px;
  background:rgba(204,68,68,.02); animation:zkFlicker 6s infinite steps(1,end); }

.zk-lg-bar  { width:3px; transform-origin:center; border-radius:1px; opacity:.6;
  background:linear-gradient(var(--red-hi), var(--red)); box-shadow:0 0 5px rgba(204,68,68,.45);
  animation:zkWave 1.4s ease-in-out infinite; }
.zk-lg-beam { position:absolute; top:0; bottom:0; width:2px; z-index:3;
  background:linear-gradient(transparent, rgba(224,92,110,.85), transparent);
  box-shadow:0 0 10px rgba(224,92,110,.6); animation:zkSweep 3.4s linear infinite; }

.zk-lg-caret { display:inline-block; width:8px; height:13px; background:var(--red-hi);
  box-shadow:0 0 7px rgba(224,92,110,.7); vertical-align:text-bottom; animation:zkBlink 1s step-end infinite; }
`;

export default function LoginPage({ onLogin }: Props) {
  const [user,    setUser]    = useState('');
  const [pass,    setPass]    = useState('');
  const [error,   setError]   = useState('');
  const [loading, setLoading] = useState(false);
  const [lines,   setLines]   = useState<BootLine[]>([]);
  const [time,    setTime]    = useState('');
  const [shake,   setShake]   = useState(0);

  useEffect(() => {
    let i = 0;
    const id = setInterval(() => {
      if (i < BOOT.length) { setLines(p => [...p, BOOT[i]]); i++; }
      else clearInterval(id);
    }, 320);
    return () => clearInterval(id);
  }, []);

  useEffect(() => {
    const tick = () => {
      const n = new Date();
      const p = (v: number) => v.toString().padStart(2, '0');
      setTime(`${p(n.getUTCHours())}:${p(n.getUTCMinutes())}:${p(n.getUTCSeconds())}Z`);
    };
    tick();
    const id = setInterval(tick, 1000);
    return () => clearInterval(id);
  }, []);

  const handleLogin = async () => {
    if (!user || !pass) {
      setError('// fault S013 — operand missing: operator id / access key required');
      setShake(s => s + 1);
      return;
    }
    setLoading(true);
    setError('');
    try {
      await auth.login(user, pass);
      onLogin();
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : 'unknown error';
      const denied = msg.includes('401') || msg.toLowerCase().includes('unauthorized');
      setError(denied
        ? '// abend S047 — operator not authorized: access denied'
        : `// fault — ${msg}`);
      setShake(s => s + 1);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{ height: '100vh', width: '100vw', background: 'var(--inset2)', position: 'relative',
      display: 'flex', alignItems: 'center', justifyContent: 'center', overflow: 'hidden',
      fontFamily: 'var(--mono)', padding: 36 }}>
      <style>{CSS}</style>

      {/* viewport vignette — corners fall into shadow */}
      <div style={{ position: 'absolute', inset: 0, zIndex: 1, pointerEvents: 'none',
        background: 'radial-gradient(ellipse 120% 100% at 50% 46%, transparent 52%, rgba(0,0,0,.62) 100%)' }} />

      {/* ── CONSOLE FRAME ── */}
      <div style={{ position: 'relative', zIndex: 2, display: 'flex', flexDirection: 'column',
        width: 'min(1240px, 95vw)', height: 'min(760px, 92vh)', background: 'var(--panel)',
        border: '2px solid var(--b3)', borderRadius: 4, overflow: 'hidden', animation: 'zkRoll .5s ease-out',
        boxShadow: 'inset 0 1px 0 #3d3d3d, inset 0 0 0 1px #333, 0 26px 72px -16px #000, 0 0 96px -10px rgba(204,68,68,.16)' }}>

        <div className="zk-lg-scan" />
        <div className="zk-lg-flicker" />

        {/* frame corner rivets */}
        <i className="zk-lg-rivet" style={{ top: 7, left: 7 }} />
        <i className="zk-lg-rivet" style={{ top: 7, right: 7 }} />
        <i className="zk-lg-rivet" style={{ bottom: 7, left: 7 }} />
        <i className="zk-lg-rivet" style={{ bottom: 7, right: 7 }} />

        {/* ── HEADER PLATE ── */}
        <div style={{ height: 60, flexShrink: 0, background: 'var(--panel2)', borderBottom: '1px solid var(--b2)',
          display: 'flex', alignItems: 'center', gap: 14, padding: '0 26px', position: 'relative', zIndex: 3,
          boxShadow: 'inset 0 -1px 0 #000' }}>
          <div style={{ width: 34, height: 34, flexShrink: 0, border: '1px solid var(--red)', background: 'var(--red3)',
            display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 18, color: 'var(--red-hi)',
            boxShadow: '0 0 10px rgba(204,68,68,.25)', textShadow: '0 0 8px rgba(224,92,110,.6)' }}>☣</div>
          <div>
            <div style={{ fontSize: 16, fontWeight: 700, color: 'var(--tx0)', letterSpacing: 3,
              textShadow: '0 1px 0 #000' }}>
              ZOMBIE KEEPER <span style={{ color: 'var(--tx2)', fontWeight: 400, letterSpacing: 2, fontSize: 12 }}>· C2 OPERATIONS CONSOLE</span>
            </div>
            <div style={{ fontSize: 9, color: 'var(--tx2)', letterSpacing: 1.5, marginTop: 2 }}>
              UNIT ZK-7 · MODEL MU/TH/UR-6000 · REV 3.0.1
            </div>
          </div>
          <div style={{ flex: 1 }} />
          <div style={{ textAlign: 'right' }}>
            <div style={{ fontSize: 13, color: 'var(--red-hi)', letterSpacing: 1, fontWeight: 700,
              textShadow: '0 0 8px rgba(224,92,110,.4)' }}>{time}</div>
            <div style={{ fontSize: 9, color: 'var(--tx2)', letterSpacing: 1, marginTop: 2 }}>
              LINK <span style={{ color: 'var(--red)', letterSpacing: 0 }}>████████░</span> 98% · CH:SECURE
            </div>
          </div>
        </div>

        {/* ── BODY ── */}
        <div style={{ flex: 1, display: 'flex', minHeight: 0, position: 'relative', zIndex: 3 }}>

          {/* LEFT — CREDENTIAL BAY */}
          <div style={{ width: 'clamp(370px, 38%, 470px)', flexShrink: 0, borderRight: '1px solid var(--b2)',
            padding: '28px 34px', display: 'flex', flexDirection: 'column', justifyContent: 'center', position: 'relative' }}>

            <div style={{ fontSize: 10, color: 'var(--tx2)', letterSpacing: 2, textTransform: 'uppercase',
              paddingBottom: 9, marginBottom: 26, borderBottom: '1px solid var(--b1)',
              display: 'flex', justifyContent: 'space-between' }}>
              <span>// credential bay</span><span style={{ color: 'var(--tx3)' }}>NEW USER #1</span>
            </div>

            <div key={shake} style={{ animation: shake ? 'zkShake .4s ease' : undefined }}>
              <div className="zk-lg-well" style={{ marginBottom: 22 }}>
                <span className="zk-lg-plate">Operator ID</span>
                <span className="zk-lg-led" />
                <input className="zk-lg-input" placeholder="operator" value={user}
                  onChange={e => setUser(e.target.value)} onKeyDown={e => e.key === 'Enter' && handleLogin()}
                  disabled={loading} autoFocus />
              </div>

              <div className="zk-lg-well" style={{ marginBottom: 18 }}>
                <span className="zk-lg-plate">Access Key</span>
                <span className="zk-lg-led" />
                <input className="zk-lg-input" type="password" placeholder="enter access key" value={pass}
                  onChange={e => setPass(e.target.value)} onKeyDown={e => e.key === 'Enter' && handleLogin()}
                  disabled={loading} />
              </div>

              {/* error strip — reserved height, no layout jump */}
              <div style={{ minHeight: 22, marginBottom: 14, display: 'flex', alignItems: 'center' }}>
                {error && (
                  <div style={{ width: '100%', fontSize: 10.5, color: 'var(--red-hi)', background: 'var(--red3)',
                    borderLeft: '2px solid var(--red-hi)', padding: '5px 9px', letterSpacing: .3 }}>
                    {error}
                  </div>
                )}
              </div>

              <button className="zk-lg-btn" onClick={handleLogin} disabled={loading}>
                {loading ? '◌  authenticating…' : '▶  initialize swarm uplink'}
              </button>
            </div>

            <i className="zk-lg-rivet" style={{ top: 16, right: 14 }} />
            <i className="zk-lg-rivet" style={{ bottom: 16, right: 14 }} />
          </div>

          {/* RIGHT — SIGNAL MONITOR */}
          <div style={{ flex: 1, padding: '24px 30px', display: 'flex', flexDirection: 'column', position: 'relative', minWidth: 0 }}>

            <div style={{ fontSize: 10, color: 'var(--tx2)', letterSpacing: 2, textTransform: 'uppercase',
              paddingBottom: 9, marginBottom: 18, borderBottom: '1px solid var(--b1)',
              display: 'flex', justifyContent: 'space-between' }}>
              <span>// signal monitor · operator pulse</span>
              <span style={{ color: 'var(--red-hi)' }}>● LIVE</span>
            </div>

            {/* oscilloscope */}
            <div style={{ height: 150, position: 'relative', overflow: 'hidden', background: 'var(--inset2)',
              border: '1px solid var(--b2)', borderRadius: 2,
              boxShadow: 'inset 0 0 40px rgba(0,0,0,.7), inset 0 0 16px rgba(204,68,68,.05)',
              backgroundImage:
                'repeating-linear-gradient(0deg, rgba(204,68,68,.05) 0 1px, transparent 1px 19px),' +
                'repeating-linear-gradient(90deg, rgba(204,68,68,.05) 0 1px, transparent 1px 19px)' }}>
              {/* baseline */}
              <div style={{ position: 'absolute', top: '50%', left: 0, right: 0, height: 1,
                background: 'rgba(224,92,110,.18)' }} />
              {/* trace bars */}
              <div style={{ position: 'absolute', inset: 0, display: 'flex', alignItems: 'center',
                justifyContent: 'space-between', padding: '0 14px' }}>
                {BARS.map(i => (
                  <span key={i} className="zk-lg-bar" style={{
                    height: '78%',
                    animationDelay: `${(i * 0.05).toFixed(2)}s`,
                    animationDuration: `${(1.1 + (i % 6) * 0.13).toFixed(2)}s`,
                  }} />
                ))}
              </div>
              {/* sweep beam */}
              <div className="zk-lg-beam" />
            </div>

            <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 10, color: 'var(--tx2)',
              letterSpacing: 1, marginTop: 8 }}>
              <span>SWEEP 50ms/div</span><span>GAIN x4</span>
              <span><span style={{ color: 'var(--red-hi)' }}>●</span> SIGNAL NOMINAL</span>
            </div>

            {/* MOTD plate */}
            <div style={{ position: 'relative', marginTop: 26, border: '1px solid var(--b2)', borderRadius: 2,
              background: 'var(--inset)', padding: '18px 20px 16px' }}>
              <span style={{ position: 'absolute', top: -7, left: 14, padding: '0 7px', background: 'var(--panel)',
                fontSize: 9, letterSpacing: 2, color: 'var(--tx2)' }}>M.O.T.D.</span>
              <div style={{ fontSize: 13, fontStyle: 'italic', color: 'var(--tx1)', lineHeight: 1.9 }}>
                The puppeteer is <span style={{ color: 'var(--red-hi)' }}>invisible</span>.
              </div>
              <div style={{ fontSize: 13, fontStyle: 'italic', color: 'var(--tx1)', lineHeight: 1.9 }}>
                The puppet believes it <span style={{ color: 'var(--red-hi)' }}>dances alone</span>.
              </div>
            </div>

            <div style={{ flex: 1 }} />
            <div style={{ textAlign: 'center', fontSize: 9, color: 'var(--tx3)', letterSpacing: 3 }}>
              ☣  AUTHORIZED ACCESS ONLY  ☣
            </div>

            <i className="zk-lg-rivet" style={{ bottom: 16, left: 14 }} />
            <i className="zk-lg-rivet" style={{ bottom: 16, right: 14 }} />
          </div>
        </div>

        {/* ── CONSOLE RAIL ── */}
        <div style={{ height: 30, flexShrink: 0, background: 'var(--inset2)', borderTop: '1px solid var(--b2)',
          display: 'flex', alignItems: 'center', gap: 12, padding: '0 16px', fontSize: 11, position: 'relative',
          zIndex: 3, overflow: 'hidden', boxShadow: 'inset 0 1px 0 #000' }}>
          <span style={{ color: 'var(--tx3)', letterSpacing: 1, flexShrink: 0 }}>CONSOLE ▏</span>
          <div style={{ flex: 1, display: 'flex', alignItems: 'center', gap: 0, whiteSpace: 'nowrap', overflow: 'hidden' }}>
            {lines.map((l, i) => (
              <span key={i} style={{ color: 'var(--tx2)', flexShrink: 0 }}>
                {i > 0 && <span style={{ color: 'var(--tx3)', margin: '0 9px' }}>▏</span>}
                {l.label}{' '}
                {l.flag && <b style={{ color: 'var(--green)', fontWeight: 700, letterSpacing: .5 }}>{l.flag}</b>}
              </span>
            ))}
            <span className="zk-lg-caret" style={{ marginLeft: 8, flexShrink: 0 }} />
          </div>
          <span style={{ color: 'var(--red)', letterSpacing: 0, flexShrink: 0 }}>████</span>
        </div>
      </div>
    </div>
  );
}
