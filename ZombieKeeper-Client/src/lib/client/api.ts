// Fala diretamente com o Spring Boot — sem proxy Next.js.
// JWT armazenado em localStorage.

import type { BackendAgentDto }  from '../dtos/agent/agentDto';
import type { C2ServerInfoDto }  from '../dtos/c2Server/c2ServerDto';
import type { UserDto, RoleDto } from '../dtos/user/user';
import type { Agent, AgentGeo }  from '../models/agents/agentModel';

export type { BackendAgentDto };
export type C2Info      = C2ServerInfoDto;
export type BackendUser = UserDto;
export type BackendRole = RoleDto;
export interface CreateUserBody { name: string; username: string; password: string; role: { name: string }; }

const API_URL = import.meta.env.VITE_API_URL ?? 'http://localhost:8080';

// ─── JWT helpers ──────────────────────────────────────────────────────────────
export function getToken(): string | null  { return localStorage.getItem('zk_token'); }
function setToken(t: string): void         { localStorage.setItem('zk_token', t); }
function clearToken(): void                { localStorage.removeItem('zk_token'); }

// ─── WebSocket URL helper (shell) ─────────────────────────────────────────────
const WS_URL = import.meta.env.VITE_WS_URL ?? 'ws://localhost:8080';
export function shellWsUrl(agentId?: string): string {
  const token = getToken() ?? '';
  return agentId
    ? `${WS_URL}/term/${agentId}?token=${token}`
    : `${WS_URL}/term?token=${token}`;
}

// ─── Fetch base ───────────────────────────────────────────────────────────────
async function req<T>(path: string, init: RequestInit = {}): Promise<T> {
  const token = getToken();
  const res = await fetch(`${API_URL}${path}`, {
    ...init,
    headers: {
      'Content-Type': 'application/json',
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...(init.headers ?? {}),
    },
  });

  if (res.status === 401) {
    clearToken();
    window.dispatchEvent(new Event('zk:logout'));
    throw new Error('Não autorizado');
  }

  if (!res.ok) {
    const msg = await res.text().catch(() => `HTTP ${res.status}`);
    throw new Error(msg);
  }

  if (res.status === 204) return undefined as T;
  return res.json();
}

// ─── Helpers de conversão ────────────────────────────────────────────────────
function elapsed(iso: string): string {
  const diff = Math.max(0, Math.floor((Date.now() - new Date(iso).getTime()) / 1000));
  const h = Math.floor(diff / 3600).toString().padStart(2, '0');
  const m = Math.floor((diff % 3600) / 60).toString().padStart(2, '0');
  const s = (diff % 60).toString().padStart(2, '0');
  return `${h}:${m}:${s}`;
}

export function mapStatus(s: BackendAgentDto['status']): 'ONLINE' | 'IDLE' | 'LOST' {
  if (s === 'ONLINE') return 'ONLINE';
  return 'LOST';
}

export function toAgent(b: BackendAgentDto): Agent {
  return {
    id:       `ZK-${b.publicId}`,
    ip:       b.ipv4        ?? '--',
    mac:      b.macAddress  ?? '--',
    hostname: b.hostname    ?? '--',
    os:       b.os          ?? '--',
    user:     b.loggedUser  ?? '--',
    priv:     b.isElevated ? 'ROOT' : 'USER',
    status:   mapStatus(b.status),
    process:  '--',
    pid:      '--',
    arch:     b.architecture ?? '--',
    lastSeen: elapsed(b.lastSeen),
    _uuid:    b.id,
  };
}

export function toAgentGeo(b: BackendAgentDto): AgentGeo | null {
  const loc = b.locations?.[0];
  if (!loc || loc.lat == null || loc.lng == null) return null;
  return {
    id:       `ZK-${b.publicId}`,
    ip:       b.ipv4     ?? '--',
    hostname: b.hostname ?? '--',
    lat:      loc.lat,
    lng:      loc.lng,
    country:  loc.country ?? '',
    city:     loc.city    ?? '',
    status:   mapStatus(b.status),
    priv:     b.isElevated ? 'ROOT' : 'USER',
  };
}

// ─── API endpoints ────────────────────────────────────────────────────────────
export const auth = {
  login: async (username: string, password: string) => {
    const data = await req<{ token: string; username: string; status: string }>(
      '/api/auth/login',
      { method: 'POST', body: JSON.stringify({ username, password }) }
    );
    setToken(data.token);
    return data;
  },
  logout: () => {
    clearToken();
    window.dispatchEvent(new Event('zk:logout'));
  },
};

export const agentsApi = {
  list:   ()           => req<BackendAgentDto[]>('/api/c2-server/agents'),
  get:    (id: string) => req<BackendAgentDto>(`/api/c2-server/agents/${id}`),
  ping:   (id: string) => req<void>(`/api/c2-server/agents/${id}/ping`,   { method: 'PUT' }),
  remove: (id: string) => req<void>(`/api/c2-server/agents/${id}/delete`, { method: 'PUT' }),
};

export const c2Api = {
  info: () => req<C2Info>('/api/c2-server/info'),
};

export const usersApi = {
  list:          ()                             => req<BackendUser[]>('/api/auth/users'),
  roles:         ()                             => req<BackendRole[]>('/api/auth/roles'),
  create:        (body: CreateUserBody)         => req<void>('/api/auth/register',              { method: 'POST',   body: JSON.stringify(body) }),
  delete:        (id: number)                   => req<void>(`/api/auth/users/${id}`,           { method: 'DELETE' }),
  updateRole:    (id: number, roleName: string) => req<BackendUser>(`/api/auth/users/${id}/role`, { method: 'PUT', body: JSON.stringify({ name: roleName }) }),
  resetPassword: (id: number, password: string) => req<void>(`/api/auth/users/${id}/password`, { method: 'PUT',   body: JSON.stringify({ password }) }),
};
