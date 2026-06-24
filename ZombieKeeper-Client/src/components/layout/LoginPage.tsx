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

const API_HEALTH = `${import.meta.env.VITE_API_URL ?? 'http://localhost:8080'}/actuator/health`;

interface Ping { ms: number; ok: boolean; }

interface Props { onLogin: () => void; }

export default function LoginPage({ onLogin }: Props) {
  const [user,    setUser]    = useState('');
  const [pass,    setPass]    = useState('');
  const [error,   setError]   = useState('');
  const [loading, setLoading] = useState(false);
  const [lines,   setLines]   = useState<BootLine[]>([]);
  const [time,    setTime]    = useState('');
  const [shake,   setShake]   = useState(0);
  const [pings,   setPings]   = useState<Ping[]>([]);
  const [apiUp,   setApiUp]   = useState<boolean | null>(null);

  useEffect(() => {
    let i = 0;
    const id = setInterval(() => {
      if (i < BOOT.length) { const item = BOOT[i]; setLines(p => [...p, item]); i++; }
      else clearInterval(id);
    }, 320);
    return () => clearInterval(id);
  }, []);

  useEffect(() => {
    let alive = true;
    const check = async () => {
      const t0 = performance.now();
      try {
        await fetch(API_HEALTH, { signal: AbortSignal.timeout(3500) });
        const ms = Math.round(performance.now() - t0);
        if (alive) { setApiUp(true);  setPings(p => [...p.slice(-39), { ms, ok: true  }]); }
      } catch {
        const ms = Math.min(Math.round(performance.now() - t0), 3500);
        if (alive) { setApiUp(false); setPings(p => [...p.slice(-39), { ms, ok: false }]); }
      }
    };
    check();
    const id = setInterval(check, 3000);
    return () => { alive = false; clearInterval(id); };
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
    <div style={{
      height: '100vh', width: '100vw',
      background: 'var(--bg)',
      display: 'flex', alignItems: 'center', justifyContent: 'center',
      fontFamily: 'var(--mono)', padding: 32,
    }}>
      <div style={{
        display: 'flex', flexDirection: 'column',
        width: 'min(1100px, 95vw)', height: 'min(680px, 92vh)',
        background: 'var(--panel)',
        border: '1px solid var(--b2)',
        boxShadow: '0 20px 60px -14px rgba(0,0,0,.75)',
        overflow: 'hidden',
        animation: 'zkRoll .4s ease-out',
      }}>

        {/* ── HEADER ── */}
        <div style={{
          height: 48, flexShrink: 0,
          background: 'var(--panel2)', borderBottom: '1px solid var(--b2)',
          display: 'flex', alignItems: 'center', gap: 11, padding: '0 16px',
        }}>
          <span style={{ fontSize: 12, color: 'var(--red-hi)', flexShrink: 0 }}>☣</span>
          <div style={{ flex: 1 }}>
            <span style={{ fontSize: 12, fontWeight: 700, color: 'var(--tx0)', letterSpacing: 1.8 }}>
              ZOMBIE KEEPER
            </span>
            <span style={{ color: 'var(--tx3)', fontWeight: 400, letterSpacing: 1.5, fontSize: 10, marginLeft: 8 }}>
              C2 OPERATIONS CONSOLE
            </span>
            <div style={{ fontSize: 9, color: 'var(--tx3)', letterSpacing: 1.5, marginTop: 2 }}>
              UNIT ZK-7 · MODEL MU/TH/UR-6000 · REV 3.0.1
            </div>
          </div>
          <div style={{ fontSize: 11, color: 'var(--tx2)', letterSpacing: 1, fontVariantNumeric: 'tabular-nums' }}>
            {time}
          </div>
        </div>

        {/* ── BODY ── */}
        <div style={{ flex: 1, display: 'flex', minHeight: 0 }}>

          {/* LEFT — CREDENTIAL BAY */}
          <div style={{
            width: 'clamp(310px, 34%, 410px)', flexShrink: 0,
            borderRight: '1px solid var(--b2)',
            display: 'flex', flexDirection: 'column',
          }}>
            <div className="sec-hdr">
              <span>credential bay</span>
              <span style={{ color: 'var(--tx3)', letterSpacing: 0, fontSize: 10 }}>SESSION #1</span>
            </div>

            <div style={{ flex: 1, padding: '20px 22px', display: 'flex', flexDirection: 'column', justifyContent: 'center' }}>
              <div key={shake} style={{ animation: shake ? 'zkShake .4s ease' : undefined }}>
                <div className="zk-lg-well" style={{ marginBottom: 14 }}>
                  <span className="zk-lg-plate">Operator ID</span>
                  <input className="zk-lg-input" placeholder="operator" value={user}
                    onChange={e => setUser(e.target.value)}
                    onKeyDown={e => e.key === 'Enter' && handleLogin()}
                    disabled={loading} autoFocus />
                </div>

                <div className="zk-lg-well" style={{ marginBottom: 12 }}>
                  <span className="zk-lg-plate">Access Key</span>
                  <input className="zk-lg-input" type="password" placeholder="enter access key" value={pass}
                    onChange={e => setPass(e.target.value)}
                    onKeyDown={e => e.key === 'Enter' && handleLogin()}
                    disabled={loading} />
                </div>

                <div style={{ minHeight: 20, marginBottom: 10 }}>
                  {error && (
                    <div style={{
                      fontSize: 10.5, color: 'var(--red-hi)',
                      background: 'var(--red3)', borderLeft: '2px solid var(--red)',
                      padding: '5px 9px', letterSpacing: .3,
                    }}>
                      {error}
                    </div>
                  )}
                </div>

                <button className="zk-lg-btn" onClick={handleLogin} disabled={loading}>
                  {loading ? '◌  authenticating…' : '▶  initialize swarm uplink'}
                </button>
              </div>

              {/* Auth subsystem status */}
              <div style={{ marginTop: 22, borderTop: '1px solid var(--b1)', paddingTop: 12 }}>
                <div style={{ fontSize: 9, color: 'var(--tx3)', letterSpacing: 1.5, textTransform: 'uppercase', marginBottom: 7 }}>
                  auth subsystems
                </div>
                {['TLS CHANNEL', 'JWT SIGNING', 'DB CONNECTION', 'LISTENER 4444'].map(label => (
                  <div key={label} style={{
                    display: 'flex', justifyContent: 'space-between', alignItems: 'center',
                    fontSize: 10, color: 'var(--tx2)', marginBottom: 4,
                  }}>
                    <span style={{ letterSpacing: .6 }}>{label}</span>
                    <span style={{ color: 'var(--green)', letterSpacing: 1, fontSize: 9 }}>■ OK</span>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* RIGHT — SIGNAL MONITOR */}
          <div style={{ flex: 1, display: 'flex', flexDirection: 'column', minWidth: 0 }}>
            <div className="sec-hdr">signal monitor</div>

            <div style={{ flex: 1, padding: '18px 20px', display: 'flex', flexDirection: 'column' }}>
              {/* API Latency monitor */}
              {(() => {
                const maxMs  = pings.length ? Math.max(...pings.map(p => p.ms), 100) : 100;
                const avgMs  = pings.length ? Math.round(pings.reduce((s, p) => s + p.ms, 0) / pings.length) : null;
                const minMs  = pings.length ? Math.min(...pings.map(p => p.ms)) : null;
                const lastMs = pings.length ? pings[pings.length - 1].ms : null;
                const barColor = (ping: Ping) => {
                  if (!ping.ok)      return 'var(--red)';
                  if (ping.ms <  80) return 'var(--green)';
                  if (ping.ms < 300) return '#c8a000';
                  return 'var(--red-hi)';
                };
                return (
                  <>
                    <div style={{
                      height: 130, flexShrink: 0,
                      position: 'relative', overflow: 'hidden',
                      background: 'var(--inset2)',
                      border: '1px solid var(--b2)',
                    }}>
                      {/* reference gridlines at 25% / 50% / 75% height */}
                      {[25, 50, 75].map(pct => (
                        <div key={pct} style={{
                          position: 'absolute', bottom: `${pct}%`, left: 0, right: 0,
                          height: 1, background: 'rgba(255,255,255,.04)',
                        }} />
                      ))}
                      {/* bar chart */}
                      <div style={{
                        position: 'absolute', inset: '0 6px 0', paddingTop: 6,
                        display: 'flex', alignItems: 'flex-end', gap: 1.5,
                      }}>
                        {pings.map((p, i) => (
                          <div key={i} style={{
                            flex: 1, minWidth: 2,
                            height: `${Math.max(4, (p.ms / maxMs) * 88)}%`,
                            background: barColor(p),
                            opacity: 0.55 + (i / pings.length) * 0.45,
                            transition: 'height .2s ease',
                          }} />
                        ))}
                        {pings.length === 0 && (
                          <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center',
                            fontSize: 10, color: 'var(--tx3)', letterSpacing: 1 }}>
                            checking api…
                          </div>
                        )}
                      </div>
                      {/* status badge — top right */}
                      <div style={{
                        position: 'absolute', top: 6, right: 8,
                        fontSize: 9, letterSpacing: 1,
                        color: apiUp === null ? 'var(--tx3)' : apiUp ? 'var(--green)' : 'var(--red-hi)',
                      }}>
                        {apiUp === null
                          ? '◌ CHECKING'
                          : apiUp
                            ? `■ UP · ${lastMs}ms`
                            : '■ OFFLINE'}
                      </div>
                    </div>

                    {/* metrics row */}
                    <div style={{
                      display: 'flex', justifyContent: 'space-between',
                      fontSize: 9, color: 'var(--tx3)', letterSpacing: 1,
                      marginTop: 5, marginBottom: 16,
                    }}>
                      <span>MIN <span style={{ color: 'var(--tx2)' }}>{minMs !== null ? `${minMs}ms` : '—'}</span></span>
                      <span>AVG <span style={{ color: 'var(--tx2)' }}>{avgMs !== null ? `${avgMs}ms` : '—'}</span></span>
                      <span>MAX <span style={{ color: 'var(--tx2)' }}>{pings.length ? `${maxMs}ms` : '—'}</span></span>
                      <span>SAMPLES <span style={{ color: 'var(--tx2)' }}>{pings.length}</span></span>
                    </div>
                  </>
                );
              })()}

              {/* MOTD */}
              <div style={{
                border: '1px solid var(--b1)', background: 'var(--inset)',
                padding: '11px 14px', position: 'relative',
              }}>
                <span style={{
                  position: 'absolute', top: -7, left: 10,
                  padding: '0 6px', background: 'var(--panel)',
                  fontSize: 9, letterSpacing: 2, color: 'var(--tx3)',
                }}>M.O.T.D.</span>
                <div style={{ fontSize: 12, fontStyle: 'italic', color: 'var(--tx1)', lineHeight: 1.8 }}>
                  The puppeteer is <span style={{ color: 'var(--red-hi)' }}>invisible</span>.
                </div>
                <div style={{ fontSize: 12, fontStyle: 'italic', color: 'var(--tx1)', lineHeight: 1.8 }}>
                  The puppet believes it <span style={{ color: 'var(--red-hi)' }}>dances alone</span>.
                </div>
              </div>

              <div style={{ flex: 1 }} />
              <div style={{ fontSize: 9, color: 'var(--tx3)', letterSpacing: 2.5, textAlign: 'center' }}>
                ☣  AUTHORIZED ACCESS ONLY  ☣
              </div>
            </div>
          </div>
        </div>

        {/* ── CONSOLE RAIL ── */}
        <div style={{
          height: 27, flexShrink: 0,
          background: 'var(--inset2)', borderTop: '1px solid var(--b2)',
          display: 'flex', alignItems: 'center', gap: 10, padding: '0 14px',
          fontSize: 10.5, overflow: 'hidden',
        }}>
          <span style={{ color: 'var(--tx3)', letterSpacing: 1, flexShrink: 0 }}>CONSOLE ▏</span>
          <div style={{ flex: 1, display: 'flex', alignItems: 'center', whiteSpace: 'nowrap', overflow: 'hidden' }}>
            {lines.map((l, i) => (
              <span key={i} style={{ color: 'var(--tx2)', flexShrink: 0 }}>
                {i > 0 && <span style={{ color: 'var(--tx3)', margin: '0 8px' }}>·</span>}
                {l.label}{' '}
                {l.flag && <b style={{ color: 'var(--green)', fontWeight: 700 }}>{l.flag}</b>}
              </span>
            ))}
            <span className="zk-lg-caret" style={{ marginLeft: 8, flexShrink: 0 }} />
          </div>
        </div>

      </div>
    </div>
  );
}
