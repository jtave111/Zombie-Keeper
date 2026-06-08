
export interface C2ServerInfoDto {
  Framework: string; 
  Uptime: string; 
  Database: string; 
  url: string;
  status: 'ONLINE' | 'OFFLINE'; 
  Listeners: string;
  lastSeen: string;
  Agents: string;
  Threads: string;
  Memory: string;
  CpuLoad: string;
  DiskFree: string;
  lat: number;
  lng: number;
  city?: string;
  country?: string;
  publicIp?: string;
  listenPort?: number;
  version?: string;
  name?: string;
  
}

