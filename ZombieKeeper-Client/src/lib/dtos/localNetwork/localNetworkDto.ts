export interface PortDto {
  id: number;
  number: number;
  proto: string;
  service: string;
  banner: string;
}

export interface VulnerabilityDto {
  id: number;
  title: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  description: string;
  evidence: string;
  cveId?: string;
  recommendation: string;
}

export interface NetworkNodeDto {
  id: number;
  ipv4: string;
  ipv6?: string;
  mac: string;
  hostname: string;
  os: string;
  architecture: string;
  status: 'UP' | 'DOWN' | 'UNKNOWN';
  firstSeen: string;
  lastSeen: string;
  vendor: string;
  isTrusted: boolean;
  vulnerabilityScore: number;
  isAgent: boolean;
  ports: PortDto[];
  vulnerabilities: VulnerabilityDto[];
}

export interface NetworkSessionDto {
  id: string;
  networkIdentifier: string;
  networkName: string;
  networkInterface: string;
  networkType: 'ETHERNET' | 'WIFI' | 'VPN' | 'BRIDGE';
  gatewayIp: string;
  subnetMask: string;
  cidr: string;
  firstSeen: string;
  lastSeen: string;
  nodes: NetworkNodeDto[];
}
