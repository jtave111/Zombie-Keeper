'use client';
import { useState } from 'react';

type SettingsTab = 'general' | 'server' | 'users' | 'database' | 'network' | 'logging' | 'about' | 'danger';

const TABS: { key: SettingsTab; label: string; icon: string }[] = [
  { key: 'general',  label: 'General',      icon: '#' },
  { key: 'server',   label: 'C2 Server',    icon: '>' },
  { key: 'users',    label: 'Users & RBAC', icon: '@' },
  { key: 'database', label: 'Database',     icon: '=' },
  { key: 'network',  label: 'Network',      icon: '*' },
  { key: 'logging',  label: 'Logging',      icon: '~' },
  { key: 'about',    label: 'About',        icon: '?' },
  { key: 'danger',   label: 'Danger Zone',  icon: '!' },
];

function Row({ label, desc, children }: { label: string; desc: string; children: React.ReactNode }) {
  return (
    <div className="setting-row">
      <div style={{ flex: 1 }}>
        <div className="setting-lbl">{label}</div>
        <div className="setting-desc">{desc}</div>
      </div>
      {children}
    </div>
  );
}

function Toggle({ on }: { on: boolean }) {
  const [v, setV] = useState(on);
  return (
    <button
      className={`zk-btn${v ? ' active' : ''}`}
      style={{ minWidth: 50, fontSize: 11 }}
      onClick={() => setV(p => !p)}
    >
      {v ? 'ON' : 'OFF'}
    </button>
  );
}

function GroupHdr({ children }: { children: React.ReactNode }) {
  return (
    <div style={{
      padding: '6px 14px',
      background: 'var(--panel2)',
      borderBottom: '1px solid var(--b1)',
      fontSize: 10,
      color: 'var(--muted)',
      textTransform: 'uppercase',
      letterSpacing: '0.8px',
    }}>
      {children}
    </div>
  );
}

function Group({ children }: { children: React.ReactNode }) {
  return (
    <div style={{ border: '1px solid var(--b2)', marginBottom: 14 }}>
      {children}
    </div>
  );
}

export default function SettingsView() {
  const [tab, setTab] = useState<SettingsTab>('general');

  return (
    <div style={{ display: 'flex', height: '100%', overflow: 'hidden' }}>

      {/* LEFT NAV */}
      <div style={{ width: 180, background: 'var(--panel)', borderRight: '1px solid var(--b2)', display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
        <div className="sec-hdr">Settings</div>
        {TABS.map(t => (
          <div
            key={t.key}
            className={`nav-item${tab === t.key ? ' active' : ''}${t.key === 'danger' ? '' : ''}`}
            style={t.key === 'danger' ? { color: 'var(--red2)', marginTop: 'auto' } : {}}
            onClick={() => setTab(t.key)}
          >
            <span className="nav-icon">{t.icon}</span>
            {t.label}
          </div>
        ))}
      </div>

      {/* CONTENT */}
      <div style={{ flex: 1, overflow: 'auto', padding: '16px 20px' }}>

        {tab === 'general' && (
          <div>
            <div style={{ marginBottom: 14 }}>
              <div style={{ fontSize: 14, color: 'var(--bright)', fontWeight: 700, marginBottom: 3 }}>General</div>
              <div style={{ fontSize: 11, color: 'var(--muted)' }}>Configurações gerais do sistema Zombie Keeper</div>
            </div>
            <Group>
              <GroupHdr>Interface</GroupHdr>
              <Row label="Operador atual" desc="Usuário autenticado nesta sessão">
                <span style={{ fontSize: 11, color: 'var(--green)', border: '1px solid var(--green2)', padding: '2px 8px' }}>ROOT_ADMIN</span>
              </Row>
              <Row label="Nome do framework" desc="Exibido na barra de título e nos logs">
                <input className="zk-input" style={{ width: 200 }} defaultValue="ZOMBIE_KEEPER" />
              </Row>
              <Row label="Versão exibida" desc="Label exibido no sidebar">
                <input className="zk-input" style={{ width: 200 }} defaultValue="C2 Framework v3.0.1" />
              </Row>
              <Row label="Relógio UTC no topbar" desc="Mostra o relógio em tempo real">
                <Toggle on={true} />
              </Row>
              <Row label="Notificações de agente" desc="Alerta quando um novo agente se conecta">
                <Toggle on={true} />
              </Row>
            </Group>
            <Group>
              <GroupHdr>Sessão</GroupHdr>
              <Row label="Timeout de sessão" desc="Tempo inativo antes de deslogar automaticamente">
                <select className="zk-select" style={{ width: 160 }}>
                  <option>30 min</option><option>1 hora</option><option>Nunca</option>
                </select>
              </Row>
              <Row label="Lock automático" desc="Bloqueia a tela ao atingir o timeout">
                <Toggle on={false} />
              </Row>
            </Group>
            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8 }}>
              <button className="zk-btn">Cancelar</button>
              <button className="zk-btn active">Salvar alterações</button>
            </div>
          </div>
        )}

        {tab === 'server' && (
          <div>
            <div style={{ marginBottom: 14 }}>
              <div style={{ fontSize: 14, color: 'var(--bright)', fontWeight: 700, marginBottom: 3 }}>C2 Server</div>
              <div style={{ fontSize: 11, color: 'var(--muted)' }}>Configurações do servidor de comando e controle</div>
            </div>
            <Group>
              <GroupHdr>Status</GroupHdr>
              <Row label="C2 Status" desc="Estado atual do servidor principal">
                <span style={{ fontSize: 11, color: 'var(--green)' }}>[*] ONLINE</span>
              </Row>
              <Row label="Listener port" desc="Porta que os agentes se conectam">
                <input className="zk-input" style={{ width: 100 }} defaultValue="4444" />
              </Row>
              <Row label="Bind address" desc="Endereço de escuta do servidor">
                <input className="zk-input" style={{ width: 160 }} defaultValue="0.0.0.0" />
              </Row>
            </Group>
            <Group>
              <GroupHdr>Heartbeat</GroupHdr>
              <Row label="Intervalo de heartbeat" desc="Frequência de ping entre servidor e agentes">
                <select className="zk-select" style={{ width: 120 }}><option>10s</option><option>30s</option></select>
              </Row>
              <Row label="Reconexão automática" desc="Tenta reconectar agentes perdidos automaticamente">
                <Toggle on={true} />
              </Row>
            </Group>
            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8 }}>
              <button className="zk-btn">Cancelar</button>
              <button className="zk-btn active">Aplicar e reiniciar listener</button>
            </div>
          </div>
        )}

        {tab === 'database' && (
          <div>
            <div style={{ marginBottom: 14 }}>
              <div style={{ fontSize: 14, color: 'var(--bright)', fontWeight: 700, marginBottom: 3 }}>Database</div>
              <div style={{ fontSize: 11, color: 'var(--muted)' }}>Configurações de conexão e manutenção do banco de dados</div>
            </div>
            <Group>
              <GroupHdr>Conexão</GroupHdr>
              <Row label="Status" desc="Estado atual da conexão com o banco">
                <span style={{ fontSize: 11, color: 'var(--green)' }}>[*] CONNECTED</span>
              </Row>
              <Row label="Host" desc="Endereço do servidor MySQL">
                <input className="zk-input" style={{ width: 180 }} defaultValue="localhost" />
              </Row>
              <Row label="Porta" desc="">
                <input className="zk-input" style={{ width: 100 }} defaultValue="3306" />
              </Row>
              <Row label="Database" desc="">
                <input className="zk-input" style={{ width: 200 }} defaultValue="zombie_keeper_db" />
              </Row>
              <Row label="Usuário" desc="">
                <input className="zk-input" style={{ width: 180 }} defaultValue="zk_admin" />
              </Row>
            </Group>
            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8 }}>
              <button className="zk-btn">Testar conexão</button>
              <button className="zk-btn active">Salvar</button>
            </div>
          </div>
        )}

        {tab === 'about' && (
          <div>
            <div style={{ marginBottom: 14 }}>
              <div style={{ fontSize: 14, color: 'var(--bright)', fontWeight: 700, marginBottom: 3 }}>About</div>
              <div style={{ fontSize: 11, color: 'var(--muted)' }}>Informações do sistema Zombie Keeper C2</div>
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8, marginBottom: 14 }}>
              {[
                ['Framework', 'ZOMBIE_KEEPER', 'C2 Framework'],
                ['Versão', 'v3.0.1', 'Build de desenvolvimento'],
                ['Backend', 'Java 21', 'Spring Boot · Hibernate · MySQL'],
                ['Frontend', 'Next.js 14', 'React · Tailwind · TypeScript'],
              ].map(([label, val, sub]) => (
                <div key={label} style={{ background: 'var(--panel)', border: '1px solid var(--b2)', padding: '12px 14px' }}>
                  <div style={{ fontSize: 9, color: 'var(--muted)', textTransform: 'uppercase', letterSpacing: 1 }}>{label}</div>
                  <div style={{ fontSize: 16, color: 'var(--bright)', fontWeight: 700, margin: '6px 0 2px' }}>{val}</div>
                  <div style={{ fontSize: 10, color: 'var(--dim)' }}>{sub}</div>
                </div>
              ))}
            </div>
            <Group>
              <GroupHdr>Módulos</GroupHdr>
              {[
                ['Agent Management', true], ['Network Recon (SpiderNETx)', true],
                ['Shell Module', false], ['Payload Generator', false],
              ].map(([name, active]) => (
                <div key={name as string} className="setting-row">
                  <span className="setting-lbl">{name as string}</span>
                  <span style={{ fontSize: 11, color: active ? 'var(--green)' : 'var(--amber2)', border: `1px solid ${active ? 'var(--green2)' : 'var(--amber)'}`, padding: '1px 8px' }}>
                    {active ? 'ATIVO' : 'EM DEV'}
                  </span>
                </div>
              ))}
            </Group>
          </div>
        )}

        {tab === 'danger' && (
          <div>
            <div style={{ marginBottom: 14 }}>
              <div style={{ fontSize: 14, color: 'var(--red2)', fontWeight: 700, marginBottom: 3 }}>[!] Danger Zone</div>
              <div style={{ fontSize: 11, color: 'var(--muted)' }}>Ações irreversíveis — use com extrema cautela</div>
            </div>
            {[
              { grp: 'AGENTES', rows: [
                { label: 'Desconectar todos os agentes', desc: 'Encerra todas as sessões ativas imediatamente', btn: 'Desconectar todos' },
                { label: 'Limpar tabela de agentes', desc: 'Remove todos os registros do banco de dados', btn: 'Limpar agentes' },
              ]},
              { grp: 'DADOS DE REDE', rows: [
                { label: 'Limpar histórico de scans', desc: 'Remove todas as NetworkSessions e NetworkNodes', btn: 'Limpar scans' },
              ]},
              { grp: 'SISTEMA', rows: [
                { label: 'Reiniciar C2 Server', desc: 'Reinicia o listener e todos os módulos', btn: 'Reiniciar' },
                { label: 'Reset de fábrica', desc: 'Apaga todos os dados e restaura configurações padrão. IRREVERSÍVEL.', btn: 'Factory Reset' },
              ]},
            ].map(section => (
              <div key={section.grp} style={{ border: '1px solid rgba(204,34,0,0.3)', marginBottom: 14 }}>
                <div style={{ padding: '6px 14px', background: 'rgba(26,4,0,0.8)', borderBottom: '1px solid rgba(204,34,0,0.2)', fontSize: 10, color: 'var(--red2)', textTransform: 'uppercase', letterSpacing: '0.8px' }}>
                  {section.grp}
                </div>
                {section.rows.map(row => (
                  <div key={row.label} className="setting-row">
                    <div style={{ flex: 1 }}>
                      <div className="setting-lbl">{row.label}</div>
                      <div className="setting-desc">{row.desc}</div>
                    </div>
                    <button className="zk-btn danger">{row.btn}</button>
                  </div>
                ))}
              </div>
            ))}
          </div>
        )}

        {(tab === 'users' || tab === 'network' || tab === 'logging') && (
          <div style={{ color: 'var(--muted)', padding: '20px 0' }}>
            <div style={{ fontSize: 12, marginBottom: 8 }}>[*] {tab.toUpperCase()} — under construction</div>
            <div style={{ fontSize: 11 }}>This module is available in the full build.</div>
          </div>
        )}
      </div>
    </div>
  );
}
