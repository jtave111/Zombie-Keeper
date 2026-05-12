import type { C2ServerInfo } from './models/c2Server/c2ServerModel';
import type { Agent, AgentGeo } from './models/agents/agentModel';

const BASE = process.env.NEXT_PUBLIC_API_URL ?? 'http://localhost:8080';

function storedToken(): string | null {
  return typeof window !== 'undefined' ? localStorage.getItem('zk_token') : null;
}

function saveToken(t: string) {
  if (typeof window !== 'undefined') localStorage.setItem('zk_token', t);
}

function clearToken() {
  if (typeof window !== 'undefined') localStorage.removeItem('zk_token');
}

async function req<T>(path: string, init: RequestInit = {}): Promise<T> {
  const t = storedToken();
  const headers: Record<string, string> = { 'Content-Type': 'application/json' };
  if (t) headers['Authorization'] = `Bearer ${t}`;

  const res = await fetch(`${BASE}${path}`, {
    ...init,
    headers: { ...headers, ...(init.headers as Record<string, string> ?? {}) },
  });

  if (!res.ok) {
    const text = await res.text().catch(() => `HTTP ${res.status}`);
    throw new Error(text || `HTTP ${res.status}`);
  }

  const ct = res.headers.get('content-type') ?? '';
  if (res.status === 204 || !ct.includes('application/json')) return undefined as T;
  return res.json();
}

// ─── Backend shapes ───────────────────────────────────────────────────────────

export interface BackendAgentDto {
  id: string;
  publicId: number;
  hostname: string;
  os: string;
  architecture: string;
  loggedUser: string;
  isElevated: boolean;
  ipv4: string;
  ipv6?: string | null;
  macAddress: string;
  status: 'OLINE' | 'OFF' | 'KILL';
  sleepTime?: number;
  firstSeen: string;
  lastSeen: string;
  locations?: Array<{
    id?: number;
    lat: number;
    lng: number;
    city?: string;
    country?: string;
    region?: string;
    source?: string;
    accuracyMeters?: number;
    capturedAt?: string;
  }> | null;
}

// Shape returned by GET /api/c2-server/info (to be created on the backend)


export interface LoginResponse {
  status: string;
  token: string;
  username: string;
  message: string;
}

// ─── Status mapping ───────────────────────────────────────────────────────────

export function mapStatus(s: BackendAgentDto['status']): 'ONLINE' | 'IDLE' | 'LOST' {
  if (s === 'OLINE') return 'ONLINE';
  return 'LOST';
}

// ─── Elapsed time helper ──────────────────────────────────────────────────────

function elapsed(iso: string): string {
  const diff = Math.max(0, Math.floor((Date.now() - new Date(iso).getTime()) / 1000));
  const h = Math.floor(diff / 3600).toString().padStart(2, '0');
  const m = Math.floor((diff % 3600) / 60).toString().padStart(2, '0');
  const s = (diff % 60).toString().padStart(2, '0');
  return `${h}:${m}:${s}`;
}

// ─── Type converters ──────────────────────────────────────────────────────────

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
  login: async (username: string, password: string): Promise<LoginResponse> => {
    const r = await req<LoginResponse>('/api/auth/login', {
      method: 'POST',
      body: JSON.stringify({ username, password }),
    });
    saveToken(r.token);
    return r;
  },
  logout:    clearToken,
  isLoggedIn: () => !!storedToken(),
};

export const agentsApi = {
  list: () => req<BackendAgentDto[]>('/api/c2-server/agents'),
  get:    (id: string) => req<BackendAgentDto>(`/api/c2-server/agents/${id}`),
  ping:   (id: string) => req<BackendAgentDto>(`/api/c2-server/agents/${id}/ping`,   { method: 'PUT' }),
  remove: (id: string) => req<void>(`/api/c2-server/agents/${id}/delete`,          { method: 'PUT' }),
};

export const c2Api = {
  info: () => req<C2ServerInfo>('/api/c2-server/info'),
};

// ─── Users & Roles ────────────────────────────────────────────────────────────

export interface BackendUser {
  id: number;
  username: string;
  name: string;
  role: string;
}

export interface BackendRole {
  id: number;
  name: string;
}

export const usersApi = {
  list:          ()                                    => req<BackendUser[]>('/api/auth/users'),
  delete:        (id: number)                          => req<void>(`/api/auth/users/${id}`,          { method: 'DELETE' }),
  updateRole:    (id: number, roleName: string)        => req<BackendUser>(`/api/auth/users/${id}/role`,  { method: 'PUT', body: JSON.stringify({ name: roleName }) }),
  resetPassword: (id: number, password: string)        => req<void>(`/api/auth/users/${id}/password`, { method: 'PUT', body: JSON.stringify({ password }) }),
  create:        (name: string, username: string, password: string, roleName: string) =>
    req<void>('/api/auth/register', { method: 'POST', body: JSON.stringify({ name, username, password, role: { name: roleName } }) }),
  roles:         ()                                    => req<BackendRole[]>('/api/auth/roles'),
};
