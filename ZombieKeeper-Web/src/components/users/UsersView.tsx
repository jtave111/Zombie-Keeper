'use client';
import { useState, useEffect, useCallback } from 'react';
import { BackendUser, BackendRole, usersApi } from '@/lib/client/api';

const ROLE_COL: Record<string, string> = {
  ADMIN:    '#e05c6e',
  OPERATOR: '#5bb8d4',
  VIEWER:   '#d48b55',
};

function roleColor(role: string) {
  for (const k of Object.keys(ROLE_COL)) if (role?.toUpperCase().includes(k)) return ROLE_COL[k];
  return '#555';
}

function roleLabel(role: string) {
  if (!role) return '—';
  return role.replace('ROLE_', '');
}

// ── Modals ────────────────────────────────────────────────────────────────────

function ModalWrap({ children, onClose }: { children: React.ReactNode; onClose: () => void }) {
  return (
    <div onClick={onClose} style={{ position:'fixed', inset:0, background:'rgba(0,0,0,0.80)', display:'flex',
      alignItems:'center', justifyContent:'center', zIndex:200, fontFamily:'Courier New' }}>
      <div onClick={e => e.stopPropagation()} style={{ background:'#0d0d0d', border:'1px solid #e05c6e',
        padding:'22px 24px', minWidth:360, maxWidth:440 }}>
        {children}
      </div>
    </div>
  );
}

function Field({ label, value, onChange, type='text', placeholder='' }:
  { label:string; value:string; onChange:(v:string)=>void; type?:string; placeholder?:string }) {
  return (
    <div style={{ marginBottom:14 }}>
      <div style={{ fontSize:9, color:'#444', textTransform:'uppercase', letterSpacing:1, marginBottom:4 }}>{label}</div>
      <input type={type} value={value} onChange={e => onChange(e.target.value)} placeholder={placeholder}
        style={{ width:'100%', background:'#080808', border:'1px solid #1a1a1a', color:'#cccccc',
          fontFamily:'Courier New', fontSize:12, padding:'6px 8px', outline:'none', boxSizing:'border-box' }}/>
    </div>
  );
}

function Btn({ label, color='#e05c6e', onClick, disabled=false }:
  { label:string; color?:string; onClick:()=>void; disabled?:boolean }) {
  return (
    <button onClick={onClick} disabled={disabled} style={{
      flex:1, background: disabled ? 'transparent' : `${color}18`,
      border:`1px solid ${disabled ? '#222' : color}`, color: disabled ? '#333' : color,
      fontFamily:'Courier New', fontSize:11, padding:'7px', cursor: disabled ? 'default' : 'pointer',
    }}>{label}</button>
  );
}

// ── Main component ────────────────────────────────────────────────────────────

export default function UsersView() {
  const [users,   setUsers]   = useState<BackendUser[]>([]);
  const [roles,   setRoles]   = useState<BackendRole[]>([]);
  const [loading, setLoading] = useState(true);
  const [error,   setError]   = useState('');
  const [search,  setSearch]  = useState('');

  // modal state
  const [modal, setModal] = useState<
    | { type: 'create' }
    | { type: 'delete';  user: BackendUser }
    | { type: 'role';    user: BackendUser }
    | { type: 'password'; user: BackendUser }
    | null
  >(null);

  // form fields
  const [fName,  setFName]  = useState('');
  const [fUser,  setFUser]  = useState('');
  const [fPass,  setFPass]  = useState('');
  const [fRole,  setFRole]  = useState('');
  const [fErr,   setFErr]   = useState('');
  const [fBusy,  setFBusy]  = useState(false);

  const load = useCallback(() => {
    setLoading(true);
    Promise.all([usersApi.list(), usersApi.roles()])
      .then(([u, r]) => { setUsers(u); setRoles(r); setError(''); })
      .catch(e => setError(`[-] ${e.message}`))
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => { load(); }, [load]);

  function openCreate() {
    setFName(''); setFUser(''); setFPass('');
    setFRole(roles[0]?.name ?? '');
    setFErr(''); setModal({ type: 'create' });
  }

  function openDelete(user: BackendUser)   { setFErr(''); setModal({ type:'delete',   user }); }
  function openRole(user: BackendUser)     { setFRole(user.role); setFErr(''); setModal({ type:'role', user }); }
  function openPassword(user: BackendUser) { setFPass(''); setFErr(''); setModal({ type:'password', user }); }

  async function submitCreate() {
    if (!fName || !fUser || !fPass || !fRole) { setFErr('All fields required'); return; }
    setFBusy(true); setFErr('');
    try { await usersApi.create({ name: fName, username: fUser, password: fPass, role: { name: fRole } }); load(); setModal(null); }
    catch (e: any) { setFErr(`[-] ${e.message}`); }
    finally { setFBusy(false); }
  }

  async function submitDelete(id: number) {
    setFBusy(true); setFErr('');
    try { await usersApi.delete(id); load(); setModal(null); }
    catch (e: any) { setFErr(`[-] ${e.message}`); }
    finally { setFBusy(false); }
  }

  async function submitRole(id: number) {
    if (!fRole) { setFErr('Select a role'); return; }
    setFBusy(true); setFErr('');
    try { await usersApi.updateRole(id, fRole); load(); setModal(null); }
    catch (e: any) { setFErr(`[-] ${e.message}`); }
    finally { setFBusy(false); }
  }

  async function submitPassword(id: number) {
    if (!fPass) { setFErr('Password required'); return; }
    setFBusy(true); setFErr('');
    try { await usersApi.resetPassword(id, fPass); setModal(null); }
    catch (e: any) { setFErr(`[-] ${e.message}`); }
    finally { setFBusy(false); }
  }

  const filtered = users.filter(u =>
    !search || [u.name, u.username, u.role].some(v => v?.toLowerCase().includes(search.toLowerCase()))
  );

  const admins    = users.filter(u => u.role?.toUpperCase().includes('ADMIN')).length;
  const operators = users.filter(u => !u.role?.toUpperCase().includes('ADMIN')).length;

  return (
    <div style={{ display:'flex', flexDirection:'column', height:'100%', overflow:'hidden',
      background:'#080808', fontFamily:'Courier New' }}>

      {/* STAT BAR */}
      <div style={{ display:'flex', flexShrink:0, borderBottom:'1px solid #111' }}>
        {[
          { l:'Total Operators', v: users.length,   c:'#cccccc' },
          { l:'Admins',          v: admins,          c:'#e05c6e' },
          { l:'Operators',       v: operators,       c:'#5bb8d4' },
          { l:'Roles',           v: roles.length,    c:'#d48b55' },
        ].map((s, i) => (
          <div key={i} style={{ flex:1, padding:'10px 16px', borderRight:'1px solid #111', background:'#0d0d0d' }}>
            <div style={{ fontSize:9, color:'#444', textTransform:'uppercase', letterSpacing:1, marginBottom:5 }}>{s.l}</div>
            <div style={{ fontSize:22, fontWeight:700, color:s.c }}>{loading ? '—' : s.v}</div>
          </div>
        ))}
      </div>

      {/* TOOLBAR */}
      <div style={{ display:'flex', alignItems:'center', gap:8, padding:'6px 12px',
        background:'#0d0d0d', borderBottom:'1px solid #111', flexShrink:0 }}>
        <input value={search} onChange={e => setSearch(e.target.value)} placeholder="search name, username, role..."
          style={{ width:260, background:'#080808', border:'1px solid #1a1a1a', color:'#e8e8e8',
            fontFamily:'Courier New', fontSize:12, padding:'5px 8px', outline:'none' }}/>
        <div style={{ marginLeft:'auto', display:'flex', gap:6 }}>
          <button onClick={load} style={{ background:'transparent', border:'1px solid #1a1a1a', color:'#444',
            fontFamily:'Courier New', fontSize:10, padding:'4px 10px', cursor:'pointer' }}>Refresh</button>
          <button onClick={openCreate} style={{ background:'#1a0000', border:'1px solid #e05c6e', color:'#e05c6e',
            fontFamily:'Courier New', fontSize:10, padding:'4px 14px', cursor:'pointer' }}>+ New Operator</button>
        </div>
      </div>

      {/* TABLE */}
      <div style={{ flex:1, overflow:'auto' }}>
        {error && (
          <div style={{ padding:'10px 14px', color:'#e05c6e', fontSize:11 }}>{error}</div>
        )}
        {loading && !error && (
          <div style={{ padding:'10px 14px', color:'#2a2a2a', fontSize:11 }}>[*] Loading operators...</div>
        )}
        {!loading && !error && (
          <table style={{ width:'100%', borderCollapse:'collapse', fontSize:12 }}>
            <thead>
              <tr style={{ background:'#111', position:'sticky', top:0, borderBottom:'1px solid #111' }}>
                {['ID','Name','Username','Role','Actions'].map(h => (
                  <th key={h} style={{ padding:'6px 14px', color:'#444', fontWeight:400, textAlign:'left',
                    fontSize:9, textTransform:'uppercase', letterSpacing:1, borderRight:'1px solid #0d0d0d', whiteSpace:'nowrap' }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {filtered.map(u => (
                <tr key={u.id}
                  onMouseEnter={e => (e.currentTarget.style.background = '#0d0d0d')}
                  onMouseLeave={e => (e.currentTarget.style.background = 'transparent')}
                  style={{ borderBottom:'1px solid #0a0a0a', cursor:'default' }}>
                  <td style={{ padding:'8px 14px', color:'#2a2a2a', borderRight:'1px solid #0a0a0a', fontSize:10 }}>{u.id}</td>
                  <td style={{ padding:'8px 14px', color:'#cccccc', borderRight:'1px solid #0a0a0a', fontWeight:700 }}>{u.name}</td>
                  <td style={{ padding:'8px 14px', color:'#5bb8d4', borderRight:'1px solid #0a0a0a' }}>{u.username}</td>
                  <td style={{ padding:'8px 14px', borderRight:'1px solid #0a0a0a' }}>
                    <span style={{ fontSize:9, padding:'2px 8px', border:`1px solid ${roleColor(u.role)}44`,
                      color:roleColor(u.role), background:`${roleColor(u.role)}11` }}>
                      {roleLabel(u.role)}
                    </span>
                  </td>
                  <td style={{ padding:'8px 14px' }}>
                    <div style={{ display:'flex', gap:4 }}>
                      <button onClick={() => openRole(u)} style={{ background:'transparent', border:'1px solid #1a1a1a',
                        color:'#555', fontFamily:'Courier New', fontSize:9, padding:'2px 7px', cursor:'pointer' }}>Role</button>
                      <button onClick={() => openPassword(u)} style={{ background:'transparent', border:'1px solid #1a3520',
                        color:'#33a84a', fontFamily:'Courier New', fontSize:9, padding:'2px 7px', cursor:'pointer' }}>Pwd</button>
                      <button onClick={() => openDelete(u)} style={{ background:'transparent', border:'1px solid #3d1520',
                        color:'#e05c6e', fontFamily:'Courier New', fontSize:9, padding:'2px 7px', cursor:'pointer' }}>Del</button>
                    </div>
                  </td>
                </tr>
              ))}
              {filtered.length === 0 && !loading && (
                <tr><td colSpan={5} style={{ padding:'12px 14px', color:'#1a1a1a', fontSize:11 }}>[*] No operators found</td></tr>
              )}
            </tbody>
          </table>
        )}
      </div>

      {/* STATUS BAR */}
      <div style={{ padding:'3px 12px', background:'#0d0d0d', borderTop:'1px solid #0d0d0d',
        flexShrink:0, display:'flex', gap:20, fontSize:10 }}>
        <span style={{ color:'#e05c6e' }}>{admins} admin{admins !== 1 ? 's' : ''}</span>
        <span style={{ color:'#5bb8d4' }}>{operators} operator{operators !== 1 ? 's' : ''}</span>
        <span style={{ marginLeft:'auto', color:'#2a2a2a' }}>
          GET /api/auth/users · POST /api/auth/register
        </span>
      </div>

      {/* ── MODALS ── */}

      {modal?.type === 'create' && (
        <ModalWrap onClose={() => setModal(null)}>
          <div style={{ fontSize:13, color:'#cccccc', fontWeight:700, marginBottom:18 }}>New Operator</div>
          <Field label="Display Name"  value={fName} onChange={setFName} placeholder="John Doe" />
          <Field label="Username"      value={fUser} onChange={setFUser} placeholder="j.doe" />
          <Field label="Password"      value={fPass} onChange={setFPass} type="password" placeholder="••••••••" />
          <div style={{ marginBottom:14 }}>
            <div style={{ fontSize:9, color:'#444', textTransform:'uppercase', letterSpacing:1, marginBottom:4 }}>Role</div>
            <select value={fRole} onChange={e => setFRole(e.target.value)}
              style={{ width:'100%', background:'#080808', border:'1px solid #1a1a1a', color:'#cccccc',
                fontFamily:'Courier New', fontSize:12, padding:'6px 8px', outline:'none' }}>
              {roles.map(r => <option key={r.id} value={r.name}>{roleLabel(r.name)}</option>)}
            </select>
          </div>
          {fErr && <div style={{ color:'#e05c6e', fontSize:10, marginBottom:10 }}>{fErr}</div>}
          <div style={{ display:'flex', gap:8 }}>
            <Btn label={fBusy ? 'Creating...' : 'Create'} onClick={submitCreate} disabled={fBusy} />
            <Btn label="Cancel" color="#444" onClick={() => setModal(null)} />
          </div>
        </ModalWrap>
      )}

      {modal?.type === 'delete' && (
        <ModalWrap onClose={() => setModal(null)}>
          <div style={{ fontSize:13, color:'#e05c6e', fontWeight:700, marginBottom:12 }}>[!] Delete Operator</div>
          <div style={{ fontSize:11, color:'#777', marginBottom:6 }}>
            This will permanently remove:
          </div>
          <div style={{ background:'#080808', border:'1px solid #1a1a1a', padding:'10px 12px', marginBottom:16 }}>
            <div style={{ color:'#cccccc', fontWeight:700 }}>{modal.user.name}</div>
            <div style={{ color:'#5bb8d4', fontSize:11, marginTop:2 }}>{modal.user.username}</div>
            <div style={{ marginTop:4 }}>
              <span style={{ fontSize:9, padding:'1px 6px', border:`1px solid ${roleColor(modal.user.role)}44`,
                color:roleColor(modal.user.role) }}>{roleLabel(modal.user.role)}</span>
            </div>
          </div>
          {fErr && <div style={{ color:'#e05c6e', fontSize:10, marginBottom:10 }}>{fErr}</div>}
          <div style={{ display:'flex', gap:8 }}>
            <Btn label={fBusy ? 'Deleting...' : 'Confirm Delete'} onClick={() => submitDelete(modal.user.id)} disabled={fBusy} />
            <Btn label="Cancel" color="#444" onClick={() => setModal(null)} />
          </div>
        </ModalWrap>
      )}

      {modal?.type === 'role' && (
        <ModalWrap onClose={() => setModal(null)}>
          <div style={{ fontSize:13, color:'#cccccc', fontWeight:700, marginBottom:6 }}>Change Role</div>
          <div style={{ fontSize:10, color:'#444', marginBottom:16 }}>{modal.user.username}</div>
          <div style={{ marginBottom:14 }}>
            <div style={{ fontSize:9, color:'#444', textTransform:'uppercase', letterSpacing:1, marginBottom:4 }}>New Role</div>
            <select value={fRole} onChange={e => setFRole(e.target.value)}
              style={{ width:'100%', background:'#080808', border:'1px solid #1a1a1a', color:'#cccccc',
                fontFamily:'Courier New', fontSize:12, padding:'6px 8px', outline:'none' }}>
              {roles.map(r => <option key={r.id} value={r.name}>{roleLabel(r.name)}</option>)}
            </select>
          </div>
          {fErr && <div style={{ color:'#e05c6e', fontSize:10, marginBottom:10 }}>{fErr}</div>}
          <div style={{ display:'flex', gap:8 }}>
            <Btn label={fBusy ? 'Saving...' : 'Save'} onClick={() => submitRole(modal.user.id)} disabled={fBusy} />
            <Btn label="Cancel" color="#444" onClick={() => setModal(null)} />
          </div>
        </ModalWrap>
      )}

      {modal?.type === 'password' && (
        <ModalWrap onClose={() => setModal(null)}>
          <div style={{ fontSize:13, color:'#cccccc', fontWeight:700, marginBottom:6 }}>Reset Password</div>
          <div style={{ fontSize:10, color:'#444', marginBottom:16 }}>{modal.user.username}</div>
          <Field label="New Password" value={fPass} onChange={setFPass} type="password" placeholder="••••••••" />
          {fErr && <div style={{ color:'#e05c6e', fontSize:10, marginBottom:10 }}>{fErr}</div>}
          <div style={{ display:'flex', gap:8 }}>
            <Btn label={fBusy ? 'Saving...' : 'Reset'} onClick={() => submitPassword(modal.user.id)} disabled={fBusy} />
            <Btn label="Cancel" color="#444" onClick={() => setModal(null)} />
          </div>
        </ModalWrap>
      )}
    </div>
  );
}
