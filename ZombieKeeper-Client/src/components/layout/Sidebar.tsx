const SECTIONS = [
  { label:'OVERVIEW', items:[
    { key:'dashboard',  icon:'#', label:'Dashboard' },
  ]},
  { label:'C2 OPERATIONS', items:[
    { key:'agents',     icon:'>', label:'Agents',        badge:'6' },
    { key:'shell',      icon:'$', label:'Shell' },
    { key:'listeners',  icon:'~', label:'Listeners',     badge:'2' },
    { key:'payloads',   icon:'*', label:'Payloads' },
    { key:'sweep',      icon:'»', label:'Sweep',         badge:'!' },
  ]},
  { label:'OPERATIONS', items:[
    { key:'operations', icon:'K', label:'Op Planner' },
    { key:'mitre',      icon:'M', label:'MITRE ATT&CK' },
    { key:'playbooks',  icon:'▶', label:'Playbooks' },
  ]},
  { label:'RECON', items:[
    { key:'scanner',    icon:'@', label:'Net Scanner' },
    { key:'network',    icon:'°', label:'Network Map' },
  ]},
  { label:'POST-EXPLOIT', items:[
    { key:'files',      icon:'/', label:'File Manager' },
    { key:'processes',  icon:'%', label:'Processes' },
    { key:'tunnels',    icon:'↔', label:'Tunnels' },
  ]},
  { label:'INTELLIGENCE', items:[
    { key:'loot',       icon:'=', label:'Loot' },
    { key:'credentials',icon:':', label:'Credentials' },
    { key:'reports',    icon:'~', label:'Reports' },
  ]},
  { label:'ARSENAL', items:[
    { key:'implants',   icon:'⚡', label:'Implants' },
    { key:'exploits',   icon:'!', label:'Exploits' },
    { key:'arsenal',    icon:'⚙', label:'Build Manager' },
  ]},
  { label:'OPSEC', items:[
    { key:'opsec',      icon:'⊘', label:'IOC Tracker' },
  ]},
  { label:'SYSTEM', items:[
    { key:'users',      icon:'@', label:'Users' },
    { key:'logs',       icon:'=', label:'Logs' },
    { key:'settings',   icon:'+', label:'Settings' },
  ]},
];

export default function Sidebar({ active, onNav }: { active:string; onNav:(k:string)=>void }) {
  return (
    <div style={{ width:196, minWidth:196, background:'#0d0d0d', borderRight:'1px solid #1a1a1a', display:'flex', flexDirection:'column', overflow:'hidden' }}>
      {/* Brand */}
      <div style={{ padding:'14px 14px 12px', borderBottom:'1px solid #1a1a1a', flexShrink:0 }}>
        <div style={{ fontSize:13, fontWeight:700, color:'#cccccc', letterSpacing:0.5, fontFamily:'Courier New' }}>ZOMBIE_KEEPER</div>
        <div style={{ fontSize:10, color:'#333', marginTop:2, fontFamily:'Courier New' }}>C2 Framework v3.0.1</div>
      </div>

      {/* Nav */}
      <div style={{ flex:1, overflowY:'auto' }}>
        {SECTIONS.map(sec => (
          <div key={sec.label}>
            <div style={{ fontSize:8, color:'#2a2a2a', textTransform:'uppercase', letterSpacing:'1.4px', padding:'10px 14px 4px', fontFamily:'Courier New' }}>
              {sec.label}
            </div>
            {sec.items.map(item => (
              <div key={item.key}
                className={`nav-item${active===item.key?' active':''}`}
                onClick={() => onNav(item.key)}>
                <span className="nav-icon" style={{ fontFamily:'Courier New' }}>{item.icon}</span>
                <span style={{ flex:1, fontFamily:'Courier New' }}>{item.label}</span>
                {item.badge && (
                  <span style={{ fontSize:9, padding:'1px 5px', background:'#1a0000', color:'#e05c6e', border:'1px solid #3d1520', fontFamily:'Courier New' }}>
                    {item.badge}
                  </span>
                )}
              </div>
            ))}
          </div>
        ))}
      </div>

      {/* Footer */}
      <div style={{ padding:'10px 14px', borderTop:'1px solid #1a1a1a', flexShrink:0 }}>
        <div style={{ display:'flex', alignItems:'center', gap:7, marginBottom:4 }}>
          <div style={{ width:6, height:6, borderRadius:'50%', background:'#33a84a', flexShrink:0 }}/>
          <span style={{ fontSize:10, color:'#33a84a', fontWeight:700, fontFamily:'Courier New' }}>C2 ONLINE</span>
        </div>
        <div style={{ fontSize:10, color:'#444', fontFamily:'Courier New' }}>op: ROOT_ADMIN</div>
        <div style={{ fontSize:10, color:'#2a2a2a', fontFamily:'Courier New' }}>role: ADMIN · RBAC</div>
      </div>
    </div>
  );
}
