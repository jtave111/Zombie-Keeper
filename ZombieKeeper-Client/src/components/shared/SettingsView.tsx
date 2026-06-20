import { useState } from 'react';

type Tab = 'general' | 'server' | 'database' | 'network' | 'security' | 'logging' | 'about' | 'danger';

const TABS: { key: Tab; label: string; icon: string }[] = [
  { key: 'general',  label: 'General',      icon: '#' },
  { key: 'server',   label: 'C2 Server',    icon: '>' },
  { key: 'database', label: 'Database',     icon: '=' },
  { key: 'network',  label: 'Network',      icon: '*' },
  { key: 'security', label: 'Security',     icon: '⊛' },
  { key: 'logging',  label: 'Logging',      icon: '~' },
  { key: 'about',    label: 'About',        icon: '?' },
  { key: 'danger',   label: 'Danger Zone',  icon: '!' },
];

function Toggle({ on }: { on: boolean }) {
  const [v, setV] = useState(on);
  return (
    <button
      className={`zk-btn${v ? ' primary' : ''}`}
      style={{ minWidth: 52, fontSize: 11 }}
      onClick={() => setV(p => !p)}
    >
      {v ? 'ON' : 'OFF'}
    </button>
  );
}

function GroupHdr({ children }: { children: React.ReactNode }) {
  return (
    <div style={{ padding:'5px 12px', background:'var(--panel2)', borderBottom:'1px solid var(--b1)', fontSize:10, color:'var(--tx2)', textTransform:'uppercase', letterSpacing:'0.8px' }}>
      {children}
    </div>
  );
}

function Group({ children }: { children: React.ReactNode }) {
  return (
    <div style={{ border:'1px solid var(--b2)', marginBottom:14, background:'var(--inset2)' }}>
      {children}
    </div>
  );
}

function Row({ label, desc, children }: { label: string; desc?: string; children: React.ReactNode }) {
  return (
    <div className="setting-row">
      <div style={{ flex:1 }}>
        <div className="setting-lbl">{label}</div>
        {desc && <div className="setting-desc">{desc}</div>}
      </div>
      {children}
    </div>
  );
}

function PageHdr({ title, sub }: { title: string; sub: string }) {
  return (
    <div style={{ marginBottom:16 }}>
      <div style={{ fontSize:13, color:'var(--tx0)', fontWeight:700, marginBottom:3 }}>{title}</div>
      <div style={{ fontSize:11, color:'var(--tx2)' }}>{sub}</div>
    </div>
  );
}

export default function SettingsView() {
  const [tab, setTab] = useState<Tab>('general');

  return (
    <div style={{ display:'flex', height:'100%', overflow:'hidden' }}>

      {/* ── Left nav ── */}
      <div style={{ width:180, background:'var(--inset2)', borderRight:'1px solid var(--b1)', display:'flex', flexDirection:'column', overflow:'hidden', flexShrink:0 }}>
        <div className="sec-hdr">Settings</div>
        {TABS.map(t => (
          <div
            key={t.key}
            onClick={() => setTab(t.key)}
            style={{
              height:28, display:'flex', alignItems:'center', gap:8, padding:'0 12px',
              fontSize:12, cursor:'pointer',
              color: tab === t.key ? 'var(--red-hi)' : t.key === 'danger' ? 'var(--red)' : 'var(--tx1)',
              background: tab === t.key ? 'var(--red2)' : 'transparent',
              borderLeft: `2px solid ${tab === t.key ? 'var(--red)' : 'transparent'}`,
            }}
            onMouseEnter={e => { if (tab !== t.key) e.currentTarget.style.background = 'var(--panel)'; }}
            onMouseLeave={e => { if (tab !== t.key) e.currentTarget.style.background = 'transparent'; }}
          >
            <span style={{ width:14, textAlign:'center', fontSize:11, color: tab === t.key ? 'var(--red)' : 'var(--tx3)', flexShrink:0 }}>{t.icon}</span>
            {t.label}
          </div>
        ))}
      </div>

      {/* ── Content ── */}
      <div style={{ flex:1, overflow:'auto', padding:'16px 20px', background:'var(--bg)' }}>

        {tab === 'general' && (
          <>
            <PageHdr title="General" sub="Interface and session configuration" />
            <Group>
              <GroupHdr>Interface</GroupHdr>
              <Row label="Current operator" desc="Authenticated user for this session">
                <span style={{ fontSize:11, color:'var(--green)', border:'1px solid var(--green2)', padding:'2px 8px' }}>ROOT_ADMIN</span>
              </Row>
              <Row label="Framework name" desc="Displayed in titlebar and logs">
                <input className="zk-input" style={{ width:200 }} defaultValue="ZOMBIE_KEEPER" />
              </Row>
              <Row label="UTC clock in menubar">
                <Toggle on={true} />
              </Row>
              <Row label="Agent connect notifications">
                <Toggle on={true} />
              </Row>
              <Row label="Sound on new agent">
                <Toggle on={false} />
              </Row>
            </Group>
            <Group>
              <GroupHdr>Session</GroupHdr>
              <Row label="Session timeout" desc="Auto-logout after idle period">
                <select className="zk-select" style={{ width:140 }}>
                  <option>30 min</option><option>1 hour</option><option>4 hours</option><option>Never</option>
                </select>
              </Row>
              <Row label="Auto-lock on timeout">
                <Toggle on={false} />
              </Row>
              <Row label="Confirm before kill all">
                <Toggle on={true} />
              </Row>
            </Group>
            <div style={{ display:'flex', justifyContent:'flex-end', gap:8 }}>
              <button className="zk-btn">Reset</button>
              <button className="zk-btn primary">Save Changes</button>
            </div>
          </>
        )}

        {tab === 'server' && (
          <>
            <PageHdr title="C2 Server" sub="Listener and connection configuration" />
            <Group>
              <GroupHdr>Status</GroupHdr>
              <Row label="Server status">
                <span style={{ fontSize:11, color:'var(--green)', display:'flex', alignItems:'center', gap:5 }}>
                  <span style={{ width:6, height:6, borderRadius:'50%', background:'var(--green)', display:'inline-block' }} />
                  ONLINE
                </span>
              </Row>
              <Row label="Uptime"><span style={{ fontSize:11, color:'var(--tx2)', fontFamily:'Courier New' }}>—</span></Row>
              <Row label="Active connections"><span style={{ fontSize:11, color:'var(--tx0)', fontFamily:'Courier New' }}>0</span></Row>
            </Group>
            <Group>
              <GroupHdr>Listener</GroupHdr>
              <Row label="Bind address" desc="Address the listener binds to">
                <input className="zk-input" style={{ width:160 }} defaultValue="0.0.0.0" />
              </Row>
              <Row label="Default agent port">
                <input className="zk-input" style={{ width:90 }} defaultValue="4444" />
              </Row>
              <Row label="HTTP listener port">
                <input className="zk-input" style={{ width:90 }} defaultValue="8443" />
              </Row>
            </Group>
            <Group>
              <GroupHdr>Heartbeat</GroupHdr>
              <Row label="Beacon interval" desc="How often agents check in">
                <select className="zk-select" style={{ width:120 }}>
                  <option>5s</option><option>10s</option><option>30s</option><option>60s</option>
                </select>
              </Row>
              <Row label="Jitter" desc="Randomness added to beacon interval">
                <select className="zk-select" style={{ width:120 }}>
                  <option>10%</option><option>20%</option><option>30%</option>
                </select>
              </Row>
              <Row label="Auto-reconnect lost agents">
                <Toggle on={true} />
              </Row>
            </Group>
            <div style={{ display:'flex', justifyContent:'flex-end', gap:8 }}>
              <button className="zk-btn">Cancel</button>
              <button className="zk-btn primary">Apply &amp; Restart Listener</button>
            </div>
          </>
        )}

        {tab === 'database' && (
          <>
            <PageHdr title="Database" sub="MySQL connection and maintenance" />
            <Group>
              <GroupHdr>Connection</GroupHdr>
              <Row label="Status">
                <span style={{ fontSize:11, color:'var(--green)', display:'flex', alignItems:'center', gap:5 }}>
                  <span style={{ width:6, height:6, borderRadius:'50%', background:'var(--green)', display:'inline-block' }} />
                  CONNECTED
                </span>
              </Row>
              <Row label="Host"><input className="zk-input" style={{ width:180 }} defaultValue="localhost" /></Row>
              <Row label="Port"><input className="zk-input" style={{ width:90 }}  defaultValue="3306" /></Row>
              <Row label="Database"><input className="zk-input" style={{ width:200 }} defaultValue="zombie_keeper_db" /></Row>
              <Row label="User"><input className="zk-input" style={{ width:180 }} defaultValue="zk_admin" /></Row>
            </Group>
            <Group>
              <GroupHdr>Maintenance</GroupHdr>
              <Row label="Auto-backup" desc="Backup database on schedule">
                <Toggle on={false} />
              </Row>
              <Row label="Backup interval">
                <select className="zk-select" style={{ width:140 }}>
                  <option>Daily</option><option>Weekly</option><option>Manual only</option>
                </select>
              </Row>
            </Group>
            <div style={{ display:'flex', justifyContent:'flex-end', gap:8 }}>
              <button className="zk-btn">Test Connection</button>
              <button className="zk-btn primary">Save</button>
            </div>
          </>
        )}

        {tab === 'security' && (
          <>
            <PageHdr title="Security" sub="JWT, authentication, and lockout policy" />
            <Group>
              <GroupHdr>Authentication</GroupHdr>
              <Row label="JWT expiration" desc="Token lifetime">
                <select className="zk-select" style={{ width:140 }}>
                  <option>1 hour</option><option>4 hours</option><option>8 hours</option><option>24 hours</option>
                </select>
              </Row>
              <Row label="Bcrypt rounds" desc="Higher = more secure but slower login">
                <select className="zk-select" style={{ width:90 }}>
                  <option>10</option><option>12</option><option>14</option>
                </select>
              </Row>
            </Group>
            <Group>
              <GroupHdr>Lockout Policy</GroupHdr>
              <Row label="Max failed login attempts">
                <input className="zk-input" style={{ width:80 }} defaultValue="5" />
              </Row>
              <Row label="Lockout duration">
                <select className="zk-select" style={{ width:140 }}>
                  <option>5 min</option><option>15 min</option><option>1 hour</option>
                </select>
              </Row>
              <Row label="Alert on brute-force">
                <Toggle on={true} />
              </Row>
            </Group>
            <Group>
              <GroupHdr>CORS</GroupHdr>
              <Row label="Allowed origins" desc="Tauri app origins (dev + prod)">
                <input className="zk-input" style={{ width:260 }} defaultValue="http://localhost:1420, tauri://localhost" />
              </Row>
            </Group>
            <div style={{ display:'flex', justifyContent:'flex-end', gap:8 }}>
              <button className="zk-btn">Cancel</button>
              <button className="zk-btn primary">Save</button>
            </div>
          </>
        )}

        {tab === 'network' && (
          <>
            <PageHdr title="Network" sub="Network interfaces and proxy configuration" />
            <Group>
              <GroupHdr>Interfaces</GroupHdr>
              {[['eth0','192.168.1.10'], ['lo','127.0.0.1'], ['tun0','10.10.10.1']].map(([iface, ip]) => (
                <Row key={iface} label={iface} desc={ip}>
                  <span className="badge badge-green">UP</span>
                </Row>
              ))}
            </Group>
            <Group>
              <GroupHdr>Geolocation</GroupHdr>
              <Row label="Provider" desc="Used for C2 and agent location on the map">
                <select className="zk-select" style={{ width:160 }}>
                  <option>ip-api.com</option><option>ipinfo.io</option>
                </select>
              </Row>
              <Row label="Auto-resolve new agents">
                <Toggle on={true} />
              </Row>
            </Group>
          </>
        )}

        {tab === 'logging' && (
          <>
            <PageHdr title="Logging" sub="Log levels and retention" />
            <Group>
              <GroupHdr>Log Level</GroupHdr>
              <Row label="Application log level">
                <select className="zk-select" style={{ width:120 }}>
                  <option>INFO</option><option>DEBUG</option><option>WARN</option><option>ERROR</option>
                </select>
              </Row>
              <Row label="Log agent events">
                <Toggle on={true} />
              </Row>
              <Row label="Log all commands">
                <Toggle on={true} />
              </Row>
              <Row label="Log to file">
                <Toggle on={false} />
              </Row>
            </Group>
            <Group>
              <GroupHdr>Retention</GroupHdr>
              <Row label="Keep logs for">
                <select className="zk-select" style={{ width:140 }}>
                  <option>7 days</option><option>30 days</option><option>90 days</option><option>Forever</option>
                </select>
              </Row>
            </Group>
          </>
        )}

        {tab === 'about' && (
          <>
            <PageHdr title="About" sub="ZombieKeeper C2 Framework" />
            <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr', gap:8, marginBottom:14 }}>
              {[
                ['Framework', 'ZOMBIE_KEEPER', 'C2 Command & Control'],
                ['Version',   'v3.0.1',        'Development build'],
                ['Backend',   'Java 21',        'Spring Boot 4 · Hibernate · MySQL 8'],
                ['Frontend',  'Tauri 2',        'React 19 · TypeScript · Tailwind'],
              ].map(([label, val, sub]) => (
                <div key={label} className="stat-box">
                  <div className="stat-box-lbl">{label}</div>
                  <div style={{ fontSize:16, color:'var(--tx0)', fontWeight:700, margin:'6px 0 2px' }}>{val}</div>
                  <div style={{ fontSize:10, color:'var(--tx2)' }}>{sub}</div>
                </div>
              ))}
            </div>
            <Group>
              <GroupHdr>Module Status</GroupHdr>
              {[
                ['Agent Management',   true ],
                ['Network Recon',      true ],
                ['C2 Shell',           true ],
                ['Payload Generator',  false],
                ['Timeline & Clipboard', true ],
              ].map(([name, active]) => (
                <div key={name as string} className="setting-row">
                  <span className="setting-lbl">{name as string}</span>
                  <span className={`badge ${active ? 'badge-green' : 'badge-dim'}`}>{active ? 'ACTIVE' : 'IN DEV'}</span>
                </div>
              ))}
            </Group>
          </>
        )}

        {tab === 'danger' && (
          <>
            <PageHdr title="⊘ Danger Zone" sub="Irreversible actions — use with extreme caution" />
            {[
              { grp:'AGENTS', rows:[
                { label:'Disconnect all agents', desc:'Terminate all active sessions immediately', btn:'Disconnect All' },
                { label:'Clear agent table',     desc:'Remove all agent records from the database', btn:'Clear Agents' },
              ]},
              { grp:'DATA', rows:[
                { label:'Clear scan history', desc:'Remove all NetworkSessions and NetworkNodes', btn:'Clear Scans' },
                { label:'Clear loot',         desc:'Delete all collected loot entries', btn:'Clear Loot' },
              ]},
              { grp:'SYSTEM', rows:[
                { label:'Restart C2 server',  desc:'Restart the listener and all modules', btn:'Restart' },
                { label:'Factory reset',      desc:'Wipe all data and restore defaults. IRREVERSIBLE.', btn:'Factory Reset' },
              ]},
            ].map(section => (
              <div key={section.grp} style={{ border:'1px solid rgba(204,68,68,0.3)', marginBottom:14, background:'var(--inset2)' }}>
                <div style={{ padding:'5px 12px', background:'var(--red3)', borderBottom:'1px solid rgba(204,68,68,0.2)', fontSize:10, color:'var(--red-hi)', textTransform:'uppercase', letterSpacing:'0.8px' }}>
                  {section.grp}
                </div>
                {section.rows.map(row => (
                  <div key={row.label} className="setting-row">
                    <div style={{ flex:1 }}>
                      <div className="setting-lbl">{row.label}</div>
                      <div className="setting-desc">{row.desc}</div>
                    </div>
                    <button className="zk-btn danger">{row.btn}</button>
                  </div>
                ))}
              </div>
            ))}
          </>
        )}
      </div>
    </div>
  );
}
