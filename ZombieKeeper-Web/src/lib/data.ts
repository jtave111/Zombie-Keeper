export type AgentStatus = 'ONLINE' | 'IDLE' | 'LOST';
export type AgentPriv   = 'ROOT' | 'USER';

export interface Agent {
  id: string; ip: string; mac: string; hostname: string; os: string;
  user: string; priv: AgentPriv; status: AgentStatus; process: string;
  pid: string; arch: string; lastSeen: string;
  _uuid?: string; // backend UUID for API operations
}

export interface Port {
  number: number; proto: string; service: string; banner?: string;
  risk?: boolean;
}

export interface Vulnerability {
  id: number; cveId?: string; cve?: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  title: string; description: string; port?: number;
  evidence?: string; recommendation?: string; remediation?: string; detectedBy?: string;
}

export interface NetworkNode {
  id: number; ipv4: string; ipv6?: string; mac: string; hostname?: string;
  os?: string; architecture?: string; status: string; vendor?: string;
  isTrusted: boolean; vulnerabilityScore: number; isAgent: boolean;
  firstSeen: string; lastSeen: string;
  ports: Port[]; vulnerabilities: Vulnerability[];
  ip?: string;
}

export interface NetworkSession {
  id: string; networkIdentifier: string; networkName: string;
  networkInterface: string; networkType: 'WIFI' | 'ETHERNET' | 'VPN';
  gatewayIp: string; subnetMask: string; cidr: string;
  firstSeen: string; lastSeen: string; nodes: NetworkNode[];
}

export interface FeedEvent { type: 'ok'|'err'|'warn'|'sys'; msg: string; time: string; }

export interface AgentGeo {
  id: string; ip: string; hostname: string; lat: number; lng: number;
  country: string; city: string; status: AgentStatus; priv: AgentPriv;
}
