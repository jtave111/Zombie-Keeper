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
  status: 'ONLINE' | 'OFF' | 'KILL';
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