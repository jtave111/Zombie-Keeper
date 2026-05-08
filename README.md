<div align="center">

<img src="https://capsule-render.vercel.app/api?type=waving&color=0d0d0d&height=220&section=header&text=Zombie%20Keeper&fontSize=80&fontColor=ff0000&animation=fadeIn&fontAlign=50" alt="Zombie Keeper" />

# Zombie Keeper — C2 Framework

**Dual-purpose Command & Control platform for infrastructure monitoring and offensive security operations**

[![Java](https://img.shields.io/badge/Java-21-ED8B00?style=for-the-badge&logo=openjdk&logoColor=white)](https://openjdk.org/projects/jdk/21/)
[![Spring Boot](https://img.shields.io/badge/Spring%20Boot-4.0-6DB33F?style=for-the-badge&logo=springboot&logoColor=white)](https://spring.io/projects/spring-boot)
[![Next.js](https://img.shields.io/badge/Next.js-15-000000?style=for-the-badge&logo=nextdotjs&logoColor=white)](https://nextjs.org/)
[![React](https://img.shields.io/badge/React-19-61DAFB?style=for-the-badge&logo=react&logoColor=black)](https://react.dev/)
[![C++](https://img.shields.io/badge/C++17-Raw%20Sockets-00599C?style=for-the-badge&logo=cplusplus&logoColor=white)](https://isocpp.org/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5-3178C6?style=for-the-badge&logo=typescript&logoColor=white)](https://www.typescriptlang.org/)
[![MySQL](https://img.shields.io/badge/MySQL-8-4479A1?style=for-the-badge&logo=mysql&logoColor=white)](https://www.mysql.com/)
[![Spring Security](https://img.shields.io/badge/Spring%20Security-JWT-4CA154?style=for-the-badge&logo=springsecurity&logoColor=white)](#)

<br/>

> ⚠️ **FOR AUTHORIZED USE ONLY** — Pentest labs, Red Team engagements with written authorization, CTF competitions, and offensive security research. Unauthorized use is illegal. Read the [Legal Notice](#-legal-notice).

</div>

---

## Table of Contents

- [Overview](#-overview)
- [Architecture](#-architecture)
- [Modules](#-modules)
  - [ZombieKeeper-Api — Spring Boot C2 Server](#zombiekeeper-api--spring-boot-c2-server)
  - [ZombieKeeper-Web — Next.js Dashboard](#zombiekeeper-web--nextjs-dashboard)
  - [Agent — C++ Network Scanner](#agent--c-network-scanner)
  - [Automation — Python Scripts](#automation--python-scripts)
- [Tech Stack](#-tech-stack)
- [Project Structure](#-project-structure)
- [Installation & Setup](#-installation--setup)
- [Usage](#-usage)
- [Roadmap](#-roadmap)
- [Legal Notice](#-legal-notice)

---

## Overview

**Zombie Keeper** is a full-stack **Command & Control (C2)** platform built from scratch for offensive security learning and controlled Red/Blue Team operations.

The system operates in three layers:

- **C2 Server** (`ZombieKeeper-Api`) — Spring Boot 4 REST API that orchestrates agents, receives network telemetry, manages sessions, and authenticates operators via JWT.
- **Web Dashboard** (`ZombieKeeper-Web`) — Next.js 15 dark-terminal UI for real-time operator interaction: agent management, shell access, network topology, payload generation, and user administration.
- **Network Agent** (`ZombieKeeper-Arsenal/cpp/`) — Native C++17 binary using Raw Sockets that performs local fingerprinting, ICMP host discovery, TCP port scanning, and reports results back to the C2 server via HTTP.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                  ZombieKeeper-Web                            │
│              Next.js 15 · React 19 · TypeScript             │
│                                                             │
│  Dashboard · Agents · Shell · Network · Payloads            │
│  Listeners · Scanner · Credentials · Users · Settings       │
└───────────────────────┬─────────────────────────────────────┘
                        │ HTTP/REST  (JWT Bearer)
                        │ http://localhost:3000 → :8080
┌───────────────────────▼─────────────────────────────────────┐
│                  ZombieKeeper-Api                            │
│              Spring Boot 4 · Java 21 · MySQL                │
│                                                             │
│  ┌─────────────────┐  ┌──────────────────┐  ┌───────────┐  │
│  │  REST Controllers│  │  Service Layer   │  │  Security │  │
│  │                 │  │                  │  │           │  │
│  │  AgentRest      │  │  AgentsService   │  │  Spring   │  │
│  │  AuthRest       │  │  AuthService     │  │  Security │  │
│  │  ReconRest      │  │  FingerprintSvc  │  │  JWT      │  │
│  └────────┬────────┘  │  ProcessMgrSvc   │  │  Roles    │  │
│           │ JPA       │  AgentLocationSvc│  └───────────┘  │
│  ┌────────▼────────────────────────────────────────────┐   │
│  │               Data Model (JPA / MySQL)              │   │
│  │  Agent · Loot · AgentLocation · NetworkSession      │   │
│  │  NetworkNode · Port · Vulnerability · User · Role   │   │
│  └─────────────────────────────────────────────────────┘   │
└──────────────────────────┬──────────────────────────────────┘
                           │ HTTP POST (scan results)
              ┌────────────▼────────────┐
              │     C++ Agent           │
              │  Linux · Raw Sockets    │
              │                         │
              │  ICMP Sweep (Ping)      │
              │  TCP Port Scanner       │
              │  FingerPrint Session    │
              │  Node · Port · Vuln     │
              └─────────────────────────┘
```

---

## Modules

### ZombieKeeper-Api — Spring Boot C2 Server

The core of the platform. Built with **Spring Boot 4 + Java 21**, it exposes a full REST API consumed by the web dashboard and by agents.

#### REST Controllers

| Controller | Path | Responsibility |
|---|---|---|
| `AgentRestController` | `/api/c2-server/agents/**` | Agent registration, listing, status, ping, deletion |
| `AuthRestController` | `/api/auth/**` | Login, user management, role management |
| `ReconRestController` | `/api/recon/**` | Receives network scan data from C++ agents |

#### Data Model

```
Agent           → compromised host (Zombie) with status, flags, tags, geo location
  └── Loot      → files / credentials extracted from the agent

NetworkSession  → full fingerprint session of a subnet
  └── NetworkNode     → discovered host in the scan
        └── Port      → open port identified on the host
              └── Vulnerability → weakness mapped to the port/service

User  → platform operator
  └── Role → access permission (ADMIN / OPERATOR)

Enums:
  Flags         → agent behavior flags
  Tags          → agent categorization
  StatusAgent   → ONLINE / OFFLINE / IDLE
  SeverityLevel → LOW / MEDIUM / HIGH / CRITICAL
  LocationSource → IP_API / MANUAL / AGENT_REPORTED
```

#### Services

| Service | Responsibility |
|---|---|
| `AgentsService` | Agent lifecycle: registration, status updates, loot retrieval |
| `AuthService` | Operator authentication with Spring Security + JWT + Roles |
| `AgentLocationService` | Geolocation tracking and enrichment of agent IPs |
| `LocalNetworkFingerprintService` | Orchestrates C++ agent execution and processes scan results |
| `LocalNetworkDatabaseManagerService` | Persists network scan data (Nodes, Ports, Vulnerabilities) |
| `ProcessManagerService` | Manages external process execution via `ProcessBuilder` |

#### Security

- **JWT** — stateless authentication with configurable expiration
- **Spring Security** — route protection with role-based access control
- **CORS** — configured for the Next.js frontend origin
- **Bcrypt** — password hashing with configurable strength

---

### ZombieKeeper-Web — Next.js Dashboard

Dark-terminal operator interface built with **Next.js 15 + React 19 + TypeScript + Tailwind CSS**.

#### Views

| View | Description |
|---|---|
| **Dashboard** | Stats overview with live agent counter and world map |
| **Agents** | Agent table with filtering, status indicators, and detail panel |
| **Shell** | Interactive command shell per agent |
| **Network** | Network topology discovered by the C++ agent |
| **Scanner** | Trigger and monitor network fingerprint sessions |
| **Payloads** | Payload generator for agent deployment |
| **Listeners** | C2 listener management |
| **Credentials** | Credentials database from loot |
| **Loot** | Exfiltrated data viewer |
| **Reports** | Report builder |
| **Users** | Operator account management (ADMIN only) |
| **Settings** | Platform configuration |

#### Key Implementation Details

- All API calls are centralized in `src/lib/api.ts` with JWT injection
- Token stored in `localStorage` under key `zk_token`
- Agent list polls every 30 seconds via `setInterval`
- World map uses Leaflet with SSR disabled via `next/dynamic`
- Backend URL configured via `NEXT_PUBLIC_API_URL` (default: `http://localhost:8080`)

---

### Agent — C++ Network Scanner

Native binary compiled in **C++17** using **POSIX Raw Sockets**. Invoked by the server via `ProcessManagerService` or deployed manually on a target host.

#### Source Structure

```
ZombieKeeper-Arsenal/cpp/
├── localFingerPrint/
│   ├── localNetwork/
│   │   ├── app/            → main.cpp, App.cpp — entry point
│   │   ├── FingerPrintSession.cpp  → orchestrates the full scan
│   │   ├── SessionBuild.cpp        → serializes and sends results via HTTP
│   │   ├── model/          → Node, Port, Session, Vulnerability
│   │   └── scanners/       → Scanner.cpp — Raw Socket TCP scan engine
│   └── Makefile
└── ping/
    └── Ping.cpp            → ICMP sweep for host discovery
```

#### Execution Flow

```
App::run()
  │
  ├─► Ping::sweep()       — ICMP packets to each IP in the subnet
  ├─► Scanner::portScan() — Raw socket scan on active hosts
  ├─► Model::build()      — Node → Port → Vulnerability per result
  └─► SessionBuild::send() — HTTP POST of full Session to C2 Server
```

**Requires root / elevated privileges** (Raw Sockets need `CAP_NET_RAW`).

---

### Automation — Python Scripts

```
ZombieKeeper-Arsenal/python/LocalFingerPrint/
└── requestAutomation/
    └── request.py    — HTTP request automation for C2 server interaction
```

---

## Tech Stack

| Component | Technology |
|---|---|
| C2 API Server | Java 21 + Spring Boot 4.0 |
| ORM / Persistence | Spring Data JPA + Hibernate + Liquibase |
| Database | MySQL 8 |
| Authentication | Spring Security + JWT + Roles |
| REST API | Spring Web MVC + Jackson |
| Web Dashboard | Next.js 15 + React 19 + TypeScript |
| UI Styling | Tailwind CSS + inline styles |
| Map | Leaflet + Leaflet.markercluster |
| Network Agent | C++17 + Raw Sockets (POSIX / Linux) |
| Build (API) | Apache Maven 3 (mvnw wrapper) |
| Build (Agent) | GNU Make |
| Build (Web) | npm / Next.js |
| Automation | Python 3 |

---

## Project Structure

```
ZombieKeeper/
│
├── ZombieKeeper-Api/                     # Spring Boot C2 Server
│   ├── src/main/java/com/manager/Zombie_Keeper/
│   │   ├── controller/                   # REST: Agent, Auth, Recon
│   │   ├── service/                      # Agents, Auth, Fingerprint, ProcessMgr, Location
│   │   ├── model/entity/                 # JPA: Agent, Loot, NetworkNode, Port, Vulnerability...
│   │   ├── model/enums/                  # Flags, Tags, StatusAgent, SeverityLevel
│   │   ├── repository/                   # Spring Data repositories
│   │   ├── dtos/                         # Request/response DTOs
│   │   ├── configuration/security/       # SecurityConfig + CorsConfig
│   │   ├── util/                         # JwtUtil
│   │   └── exception/                    # DuplicateAgentException
│   ├── src/main/resources/
│   │   └── application.properties        # Server configuration
│   ├── .env                              # Environment variables (gitignored)
│   └── pom.xml
│
├── ZombieKeeper-Web/                     # Next.js Dashboard
│   ├── src/
│   │   ├── app/                          # Next.js App Router (layout + root page)
│   │   ├── components/                   # React components by feature
│   │   │   ├── layout/                   # App, LoginPage, Menubar, Sidebar
│   │   │   ├── agents/                   # AgentsView, AgentShell, AgentTableHeader
│   │   │   ├── dashboard/                # DashboardView, WorldMap
│   │   │   ├── network/                  # NetworkView
│   │   │   ├── scanner/                  # ScannerView
│   │   │   ├── payloads/                 # PayloadGenerator
│   │   │   ├── listeners/                # ListenersView
│   │   │   ├── intelligence/             # CredentialsView, LootView, ReportsView
│   │   │   ├── users/                    # UsersView
│   │   │   └── shared/                   # SettingsView
│   │   ├── lib/                          # api.ts, data.ts, networkData.ts
│   │   └── styles/                       # globals.css (Tailwind + CSS vars)
│   ├── .env.local                        # NEXT_PUBLIC_API_URL (gitignored)
│   └── package.json
│
├── ZombieKeeper-Arsenal/                              # All native agents, exploits & automation
│   ├── cpp/
│   │   ├── LocalFingerPrint/             # C++17 network fingerprint agent
│   │   │   ├── localNetwork/             # Scanner, FingerPrintSession, Models
│   │   │   │   ├── app/                  # main.cpp, App.cpp — entry point
│   │   │   │   ├── model/               # Node, Port, Session, Vulnerability
│   │   │   │   └── scanners/            # Raw Socket TCP scan engine
│   │   │   └── Makefile
│   │   └── Ping/                         # ICMP sweep library (used by LocalFingerPrint)
│   │       ├── Ping.cpp
│   │       └── h/Ping.h
│   ├── python/
│   │   └── LocalFingerPrint/             # HTTP automation scripts
│   │       └── requestAutomation/
│   ├── go/                               # Go agent & tools (planned)
│   ├── rust/                             # Rust implant & tools (planned)
│   ├── assembly/                         # x86-64 shellcode & exploits (planned)
│   └── windows/                          # Windows agent (planned)
│
├── pom.xml                               # Maven aggregator (monorepo root)
├── start.sh                              # Startup script for all services
└── README.md
```

---

## Installation & Setup

### Prerequisites

| Tool | Version | Purpose |
|---|---|---|
| Java (JDK) | 21+ | C2 API Server |
| Maven | 3.8+ | Build tool (or use `mvnw` wrapper) |
| Node.js | 20+ | Web dashboard |
| MySQL | 8+ | Database |
| GCC / G++ | 11+ with C++17 | C++ agent (Linux) |
| Python | 3.10+ | Automation scripts |

> Raw Sockets require **root or `CAP_NET_RAW`** on the host running the C++ agent.

---

### 1. Clone the repository

```bash
git clone https://github.com/jtave111/ZombieKeeper.git
cd ZombieKeeper
```

### 2. Configure environment variables

```bash
# Copy and edit the API environment file
cp ZombieKeeper-Api/.env.example ZombieKeeper-Api/.env
# Edit with your database credentials, JWT secret, etc.
nano ZombieKeeper-Api/.env

# Copy and edit the Web environment file
cp ZombieKeeper-Web/.env.local.example ZombieKeeper-Web/.env.local
# Set NEXT_PUBLIC_API_URL to your API server address
nano ZombieKeeper-Web/.env.local
```

**Minimum required variables in `ZombieKeeper-Api/.env`:**

```env
DB_HOST=localhost
DB_PORT=3306
DB_NAME=c2_db
DB_USERNAME=your_db_user
DB_PASSWORD=your_db_password
JWT_SECRET=your-secret-key-at-least-32-chars
ADMIN_USERNAME=admin
ADMIN_PASSWORD=YourSecurePassword!
```

**Minimum required in `ZombieKeeper-Web/.env.local`:**

```env
NEXT_PUBLIC_API_URL=http://localhost:8080
```

### 3. Start all services (recommended)

```bash
# Start API + Web dashboard
./start.sh

# Build API first, then start everything
./start.sh --build

# Start only the API
./start.sh --api-only

# Start only the Web dashboard
./start.sh --web-only
```

### 4. Manual startup

**API Server:**
```bash
cd ZombieKeeper-Api
./mvnw spring-boot:run
# API available at http://localhost:8080
```

**Web Dashboard:**
```bash
cd ZombieKeeper-Web
npm install
npm run dev
# Dashboard available at http://localhost:3000
```

### 5. Compile the C++ Agent (Linux)

```bash
cd ZombieKeeper-Arsenal/cpp/LocalFingerPrint
make
# Binary: ./LocalFingerPrint
```

**Run the agent** (requires root):
```bash
sudo ./LocalFingerPrint
```

---

## Usage

### Operator Workflow

**1. Login** — Access `http://localhost:3000` and authenticate with your operator credentials.

**2. Dashboard** — Overview panel showing active agent count, total agents, and a world map with agent geolocations.

**3. Agents** — Full agent table with status (`ONLINE` / `OFFLINE` / `IDLE`), flags, tags, and last seen. Double-click an agent to open its shell.

**4. Shell** — Interactive command interface for an active agent.

**5. Scanner** — Trigger a local network fingerprint session. The server will invoke the C++ binary on the target agent, which scans the subnet and reports back.

**6. Network** — Visualize the discovered topology: hosts, open ports, and mapped vulnerabilities with severity levels.

**7. Payloads** — Generate deployment payloads for new agents.

**8. Users** — (ADMIN only) Create, update, and remove operator accounts and manage role assignments.

---

## Roadmap

> Legend: **[x]** Done · **[~]** In Progress (UI built, backend pending) · **[ ]** Planned

---

**C2 Server (API)**
- [x] Spring Boot 4 REST API + Spring Security + JWT + Roles
- [x] Full data model: Agent, Loot, NetworkSession, NetworkNode, Port, Vulnerability
- [x] Agent geolocation tracking (`AgentLocation` + `AgentLocationService`)
- [x] `ProcessManagerService` for external binary execution
- [x] Liquibase database migrations
- [x] CORS + security configuration for web frontend
- [ ] `GET /api/c2-server/sessions` — network session listing endpoint
- [ ] WebSocket channel for real-time agent ↔ server communication
- [ ] Loot: file upload, storage, and download endpoints
- [ ] Listener management API (create, list, stop)
- [ ] Credentials storage and retrieval API
- [ ] Session report generation (PDF / JSON export)
- [ ] Settings persistence API (server config, C2 parameters)
- [ ] MITRE ATT&CK Navigator integration
- [ ] CVE auto-correlation via NVD API

---

**Web Dashboard**
- [x] Dark terminal UI with full operator navigation (12 views)
- [x] Login with JWT authentication
- [x] Dashboard with live agent stats and Leaflet world map
- [x] Agent table — real API, filtering, search, kill action
- [x] User management — full CRUD with role assignment (real API)
- [~] Agent Shell — terminal UI done, responses are hardcoded (need real command execution)
- [~] Agent Shell tabs — Process List, File Manager, Port Forward, Sysinfo (UI built, no backend)
- [~] Network Scanner view — UI + command builder done, scan execution is simulated
- [~] Payload Generator — full config UI done, build output is fake (no real binary generation)
- [~] Network Topology view — UI built, waiting for `GET /api/c2-server/sessions` endpoint
- [~] Report Builder — section picker and format selector done, no actual report generation
- [~] Settings — all tabs UI complete, no persistence (save/test buttons non-functional)
- [ ] Listeners view — backend integration (UI is empty placeholder)
- [ ] Credentials view — backend integration (UI is empty placeholder)
- [ ] Loot file browser, preview, and download
- [ ] Real-time operator feed via WebSocket
- [ ] Network topology graph (D3.js or vis.js)
- [ ] Shell — real command execution piped to agent
- [ ] Payload download after generation
- [ ] Report export (PDF / HTML)

---

**C++ Agent (Linux)**
- [x] ICMP sweep for host discovery (`Ping.cpp`)
- [x] TCP port scanner via Raw Sockets (`Scanner.cpp`)
- [x] Session model: Node → Port → Vulnerability
- [x] Session serialization and HTTP POST to C2 server
- [x] Linux build via GNU Make
- [ ] Service banner grabbing (identify service versions on open ports)
- [ ] OS fingerprinting via TTL / TCP stack analysis
- [ ] Keep-alive beacon with configurable check-in interval
- [ ] Bi-directional C2 channel (receive and execute server commands)
- [ ] File exfiltration module (read + HTTP POST loot)
- [ ] Automated CVE correlation for discovered service versions
- [ ] Post-exploitation: privilege escalation checks
- [ ] Post-exploitation: persistence mechanisms (cron, systemd)

---

**C++ Agent (Windows)**
- [ ] WinSock2 port of the network scanner
- [ ] Windows service banner grabbing
- [ ] Agent registration via HTTP (structure exists in `ZombieKeeper-Arsenal/windows/`)
- [ ] Build via MSVC / CMake
- [ ] Process hollowing — spawn a legitimate process and replace its memory
- [ ] DLL injection via `CreateRemoteThread` + `LoadLibrary`
- [ ] Reflective DLL injection (no disk write, in-memory only)
- [ ] Token impersonation — steal tokens from high-privilege processes
- [ ] UAC bypass techniques (fodhelper, CMSTPLUA, etc.)
- [ ] Persistence: Registry (`Run` keys, service installation)
- [ ] Persistence: Scheduled Tasks via COM (`ITaskService`)
- [ ] Persistence: WMI event subscription
- [ ] LSASS credential dump (Mimikatz-style, in-memory)
- [ ] SAM / NTDS hash extraction
- [ ] ETW (Event Tracing for Windows) patching to blind defenders
- [ ] AMSI bypass techniques (patching `amsi.dll` in memory)
- [ ] Windows Defender exclusion path abuse

---

**Go Modules** *(planned — `ZombieKeeper-Arsenal/go/`)*
- [ ] High-performance concurrent port scanner (goroutine pool)
- [ ] Agent beacon / implant — cross-compile to Linux / Windows / macOS
- [ ] HTTP/S C2 comms with TLS + certificate pinning
- [ ] mTLS mutual authentication between agent and server
- [ ] DNS-over-HTTPS covert channel (DoH C2)
- [ ] Domain fronting via CDN headers
- [ ] Traffic obfuscation — HTTP C2 disguised as legitimate browsing
- [ ] In-memory payload execution (no disk write, `memfd_create` on Linux)
- [ ] SOCKS5 proxy pivot through compromised host
- [ ] Port forwarding / reverse tunnel via SSH or raw TCP
- [ ] Go-based implant with staged payload (stager → full agent)
- [ ] Process injection via `ptrace` (Linux) / `NtWriteVirtualMemory` (Windows)
- [ ] ELF / PE packer to reduce binary signatures
- [ ] Polymorphic stub generator (randomize binary layout per build)

---

**Rust Modules** *(planned — `ZombieKeeper-Arsenal/rust/`)*
- [ ] Memory-safe network scanner (replaces C++ scanner long-term)
- [ ] Rust-based implant — minimal footprint, no runtime dependencies
- [ ] BOF (Beacon Object File) compatible modules
- [ ] Encrypted payload dropper
- [ ] Anti-debug and anti-sandbox checks
- [ ] Custom TLS stack with traffic fingerprint evasion
- [ ] Kernel module / rootkit prototype (Linux LKM, lab only)

---

**PowerShell / .NET** *(planned — `ZombieKeeper-Arsenal/windows/powershell/`)*
- [ ] PowerShell agent — runs entirely in memory (`IEX` / `Invoke-Expression`)
- [ ] PowerShell AMSI bypass one-liners (lab reference)
- [ ] .NET (C#) agent using `System.Reflection` for in-memory assembly loading
- [ ] BloodHound-style AD enumeration (users, groups, ACLs, GPOs)
- [ ] Kerberoasting — SPN enumeration + TGS ticket extraction
- [ ] AS-REP Roasting — attack accounts with pre-auth disabled
- [ ] Pass-the-Hash via `sekurlsa::pth` wrapper
- [ ] Pass-the-Ticket (import forged Kerberos tickets)
- [ ] DCSync attack — simulate domain controller replication to dump hashes
- [ ] LDAP enumeration (users, computers, trusts, domain info)
- [ ] SMB enumeration (shares, sessions, users via NetAPI)

---

**Assembly / Shellcode / Exploit Development** *(planned — `ZombieKeeper-Arsenal/assembly/`)*
- [ ] x86-64 shellcode stubs — Linux `execve("/bin/sh")` via raw syscalls
- [ ] x86-64 shellcode stubs — Windows `WinExec` / reverse shell via WinSock2
- [ ] Position-independent shellcode (PIC) — no hardcoded addresses
- [ ] Staged shellcode loader (stager downloads and executes second stage)
- [ ] XOR / AES encrypted shellcode with runtime decryption stub
- [ ] Stack-based buffer overflow exploit templates (ret2win, ret2libc)
- [ ] ret2syscall chain construction helpers
- [ ] ROP gadget finder integration (ROPgadget / ropper output parser)
- [ ] ROP chain builder for bypassing NX/DEP
- [ ] SROP — Sigreturn-Oriented Programming exploit template
- [ ] Format string vulnerability exploit templates (`%n` write-what-where)
- [ ] Heap exploitation templates — tcache poisoning, fastbin dup
- [ ] Use-After-Free (UAF) exploit template
- [ ] Integer overflow → heap overflow exploit template
- [ ] Type confusion exploit template (C++ vtable hijack)
- [ ] ELF injection — parasitic code injection into existing binaries
- [ ] PE injection — inject code into Windows PE headers
- [ ] ASLR leak techniques (format string, partial overwrite)
- [ ] Kernel exploit templates (lab VMs only): `commit_creds` ret2user, dirty pipe style

---

**Network Recon & OSINT** *(planned — `ZombieKeeper-Arsenal/recon/`)*
- [ ] Subdomain enumeration (brute-force + certificate transparency logs)
- [ ] DNS zone transfer attempt + DNS enumeration
- [ ] WHOIS / ASN lookup and IP range mapping
- [ ] Shodan API integration — passive host discovery
- [ ] Web application fingerprinting (tech stack detection)
- [ ] Directory and file brute-force (gobuster-style)
- [ ] Web crawling and link extraction
- [ ] SSL/TLS certificate analysis and misconfiguration detection
- [ ] SMTP enumeration (VRFY, EXPN, user enumeration)
- [ ] SNMP enumeration (community string brute-force, MIB walk)
- [ ] LDAP anonymous bind enumeration
- [ ] SMB null session and share enumeration
- [ ] FTP anonymous login check + directory traversal

---

**Post-Exploitation Framework** *(planned)*
- [ ] Screenshot capture (X11 / Win32 GDI)
- [ ] Keylogger module (X11 `XRecord` / Win32 `SetWindowsHookEx`)
- [ ] Clipboard monitor and exfiltration
- [ ] Browser credential extraction (Chromium SQLite, Firefox key4.db)
- [ ] SSH known_hosts and private key harvesting
- [ ] Environment variable and secrets scanning (`.env`, AWS keys, tokens)
- [ ] Docker socket abuse for container escape
- [ ] Sudo misconfiguration checker (GTFOBins-style)
- [ ] SUID/SGID binary enumeration
- [ ] Cron job hijacking opportunities scanner
- [ ] `/proc` memory scraping for credentials in running processes
- [ ] Lateral movement: SSH agent forwarding abuse
- [ ] Lateral movement: credential re-use scanner across discovered hosts

---

**Evasion & Anti-Forensics** *(planned)*
- [ ] Process name spoofing (`argv[0]` manipulation on Linux)
- [ ] File timestamp manipulation (timestomping)
- [ ] Log tampering — selective `wtmp` / `auth.log` entry removal
- [ ] Memory-only execution — no artifact on disk
- [ ] C2 traffic mimicry (disguise as HTTPS, DNS, or WebSocket)
- [ ] Sleep obfuscation — encrypt implant memory during sleep intervals
- [ ] Unhooking EDR hooks in `ntdll.dll` (Windows, fresh copy from disk)
- [ ] Heaven's Gate technique (32-bit → 64-bit call transition)

---

**Python — Attacks & Offensive Tooling** *(planned — `ZombieKeeper-Arsenal/python/`)*
- [x] HTTP request automation base (`request.py`)
- [ ] Full agent registration and check-in automation
- [ ] Offline network session parser and report generator
- [ ] Service version → CVE lookup automation (NVD / OSV API)
- [ ] Custom wordlist generator from OSINT target info (names, dates, keywords)
- [ ] Automated recon → exploit selection → report pipeline (lab environments)
- [ ] **Network attacks**
  - [ ] ARP spoofing + MITM traffic interceptor (`scapy`)
  - [ ] ARP cache poisoning to redirect subnet traffic
  - [ ] DNS spoofing — intercept and forge DNS responses on LAN
  - [ ] DHCP starvation + rogue DHCP server (redirect default gateway)
  - [ ] ICMP redirect attack to hijack routing tables
  - [ ] TCP session hijacking (RST injection, sequence prediction)
  - [ ] SSL stripping — downgrade HTTPS to HTTP on MITM position
  - [ ] LLMNR / NBT-NS / mDNS poisoning (`Responder`-style)
  - [ ] IPv6 rogue router advertisement (SLAAC attack)
  - [ ] STP (Spanning Tree) BPDU manipulation — become root bridge
  - [ ] VLAN hopping via 802.1Q double-tagging
  - [ ] 802.1X EAP downgrade and identity harvesting
- [ ] **Web application attacks**
  - [ ] SQL injection fuzzer with blind / time-based detection
  - [ ] XSS payload injector and reflective scanner
  - [ ] SSRF probe — internal network discovery via vulnerable parameter
  - [ ] XXE injection tester (file read + SSRF via XML parser)
  - [ ] SSTI detection (Server-Side Template Injection — Jinja2, Twig, Freemarker)
  - [ ] Directory traversal / path traversal fuzzer
  - [ ] JWT tampering toolkit (none alg, RS256→HS256, brute-force weak secrets)
  - [ ] OAuth 2.0 flow attack — state parameter bypass, open redirect
  - [ ] CORS misconfiguration scanner
  - [ ] GraphQL introspection + batch query attack
  - [ ] HTTP request smuggling (CL.TE / TE.CL) probe
  - [ ] Deserialization payload generator (Java / PHP / Python pickle)
  - [ ] Web cache poisoning detector
- [ ] **Credential attacks**
  - [ ] SSH brute-force with threading and delay jitter (`paramiko`)
  - [ ] FTP / Telnet / RDP credential spraying
  - [ ] HTTP Basic / Digest / Form-based auth brute-force
  - [ ] Hash cracking helper — MD5, SHA1, NTLM wordlist attack
  - [ ] Default credential scanner across discovered services
  - [ ] Credential stuffing with proxy rotation
- [ ] **Phishing & Social Engineering** *(authorized engagements only)*
  - [ ] Email phishing payload generator with embedded macro docs
  - [ ] HTML phishing page cloner
  - [ ] SMS / vishing pretexting script templates
  - [ ] QR code phishing generator (Wi-Fi, URL)
  - [ ] Malicious PDF / DOCX with auto-executing payload

---

**Network Protocol Attacks** *(planned — `ZombieKeeper-Arsenal/network/`)*
- [ ] **Layer 2**
  - [ ] MAC flooding — overflow CAM table, force hub behavior on switch
  - [ ] ARP watch / detection evasion (randomize timing and source MAC)
  - [ ] CDP / LLDP spoofing — impersonate Cisco/network equipment
  - [ ] EtherChannel negotiation abuse (PAgP / LACP)
- [ ] **Layer 3 / Routing**
  - [ ] BGP hijacking simulation (lab — route injection via `GoBGP`)
  - [ ] OSPF / RIP route injection (fake LSA / RIP response)
  - [ ] IP fragmentation attack (overlapping fragments bypass IDS)
  - [ ] TTL manipulation for firewall evasion
  - [ ] Covert channel via IP header fields (ID field, ToS, options)
- [ ] **Layer 4 / Transport**
  - [ ] SYN flood with randomized source IPs (raw socket)
  - [ ] UDP flood and UDP amplification (DNS, NTP, SSDP, memcached)
  - [ ] TCP RST injection to terminate active connections
  - [ ] QUIC protocol analysis and manipulation
- [ ] **Wireless (802.11)**
  - [ ] Wi-Fi deauthentication attack (IEEE 802.11 management frame injection)
  - [ ] WPA2 4-way handshake capture + offline crack (hashcat integration)
  - [ ] PMKID attack (clientless WPA2 crack)
  - [ ] Evil Twin AP — rogue access point with captive portal
  - [ ] WPS PIN brute-force (Pixie Dust attack)
  - [ ] Beacon flood — fake SSIDs to confuse clients
  - [ ] Karma attack — respond to all probe requests
  - [ ] WPA3 Dragonblood downgrade (side-channel timing)
  - [ ] Bluetooth LE scanning, spoofing, and MITM (`btlejack` style)
  - [ ] BLE credential sniffing from IoT devices
- [ ] **VPN & Tunneling**
  - [ ] IKE/IPSec aggressive mode fingerprinting
  - [ ] OpenVPN traffic fingerprinting and manipulation
  - [ ] DNS tunneling — data exfiltration via DNS TXT/A records
  - [ ] ICMP tunneling — covert channel inside ICMP echo payloads
  - [ ] HTTP tunneling through proxies and deep packet inspection firewalls

---

**Other Languages — Attack Modules** *(planned)*

*Bash / Shell*
- [ ] Reverse shell one-liner collection (Linux / macOS reference)
- [ ] Linux local enumeration script (linPEAS-style from scratch)
- [ ] Automated cron-based persistence installer
- [ ] Live memory forensics helper (read `/proc/[pid]/mem`)
- [ ] Fileless C2 beacon (`curl` + sleep loop, no binary on disk)
- [ ] SSH tunneling and port-forward automation scripts

*Lua*
- [ ] Nmap NSE script — custom vulnerability checks for discovered services
- [ ] Nmap NSE brute-force module for proprietary protocols
- [ ] Nmap NSE banner parser with CVE mapping output

*Ruby*
- [ ] Metasploit auxiliary module templates (custom recon + exploit)
- [ ] Rails / Rack application security scanner
- [ ] Custom fuzzer for binary network protocols

*Nim*
- [ ] Implant that compiles to C with minimal AV signatures
- [ ] Shellcode loader with direct syscall evasion
- [ ] Cross-compiler targeting Windows PE from Linux

*Kotlin / JVM*
- [ ] Android APK backdoor via smali patching + repack
- [ ] Android reverse shell using accessibility service
- [ ] JVM deserialization exploit toolkit (ysoserial-style gadget chains)
- [ ] Spring Boot RCE via SPEL injection / Actuator misconfiguration

*JavaScript / Node.js*
- [ ] XSS payload that upgrades to a BeEF-style in-browser agent
- [ ] Node.js SSRF and prototype pollution exploit demos
- [ ] Electron app RCE via `nodeIntegration` + `contextIsolation` bypass
- [ ] WebSocket-based browser C2 channel

*PHP*
- [ ] Webshell collection (minimal, obfuscated, image-disguised variants)
- [ ] Object injection POP chain gadget builder
- [ ] LFI → RCE via log poisoning and `/proc/self/fd`

---

**Hardware Hacking** *(planned — `ZombieKeeper-Arsenal/hardware/`)*

*Microcontrollers & Single-Board Computers*
- [ ] **Arduino / ATmega** — USB HID attack (BadUSB): keystroke injection payloads for Linux and Windows
- [ ] **Rubber Ducky** compatible payload scripts (DuckyScript format)
- [ ] **Digispark** (ATtiny85) — smallest possible BadUSB for covert drop
- [ ] **Raspberry Pi Zero W** — headless Wi-Fi drop implant with reverse SSH tunnel to C2
- [ ] **Raspberry Pi** — network tap: passive traffic capture + automatic exfiltration
- [ ] **ESP8266 / ESP32** — Wi-Fi deauth beacon, evil twin AP, and captive portal (no PC needed)
- [ ] **ESP32 Bluetooth** — BLE scanner, spoofer, and sniffer
- [ ] **Flipper Zero** — payload scripts: SubGHz replay attacks, NFC/RFID cloning, IR blaster, BadUSB

*RFID / NFC / Smart Cards*
- [ ] RFID 125kHz (EM4100 / HID Prox) card cloning with `Proxmark3`
- [ ] MIFARE Classic 1K crack (nested authentication + darkside attack)
- [ ] MIFARE Ultralight clone and UID manipulation
- [ ] NFC payment card data harvesting (contactless skimming, lab)
- [ ] Smart card (ISO 7816) APDU fuzzing
- [ ] RFID replay attack — capture → replay to gain physical access

*Software Defined Radio (SDR)*
- [ ] RF signal recording and replay with `RTL-SDR` / `HackRF`
- [ ] 433 MHz / 868 MHz remote control replay (garage doors, car keys)
- [ ] Rolling code analysis (KeeLoq weak implementations)
- [ ] Tire Pressure Monitor (TPMS) packet decoding and spoofing
- [ ] Pager (POCSAG / FLEX) interception and decoder
- [ ] ADS-B aircraft transponder spoofing (lab simulation)
- [ ] GSM / 4G LTE IMSI catcher simulation (`gr-gsm`, `srsRAN`)
- [ ] Z-Wave / Zigbee IoT protocol sniffing and injection

*Serial / Debug Interfaces*
- [ ] UART console access via `screen` / `minicom` — dump bootloader and root shell
- [ ] JTAG / SWD debugging interface identification and exploitation (extract firmware)
- [ ] I2C / SPI bus sniffing — extract EEPROM contents (credentials, private keys)
- [ ] CAN bus (automotive) — read and inject frames (`SocketCAN`, `can-utils`)
- [ ] OBD-II port attack — vehicle ECU manipulation (lab / own vehicle)
- [ ] USB fuzzing — malformed descriptor injection to crash / exploit USB host drivers

*Firmware Analysis & Modification*
- [ ] Firmware extraction via `binwalk` + entropy analysis
- [ ] Filesystem unpacking and secrets extraction (hardcoded creds, private keys)
- [ ] Firmware re-packing and flashing modified image
- [ ] Bootloader unlocking techniques (U-Boot interrupt, UART shell)
- [ ] Secure Boot bypass via glitching or misconfigured trust chain
- [ ] TP-Link / D-Link / Netgear router firmware exploitation (known CVEs + 0-day methodology)

*Physical & Side-Channel*
- [ ] Power analysis attack (SPA / DPA) on microcontroller crypto (ChipWhisperer)
- [ ] Electromagnetic fault injection (EMFI) — glitch to skip firmware security checks
- [ ] Timing side-channel attack on AES / RSA implementations
- [ ] Cold boot attack — RAM content recovery after power cut
- [ ] Acoustic side-channel (keyboard/HDD noise analysis, lab demo)
- [ ] USB power line monitoring to detect keystrokes (USB power glitch)

---

**Infrastructure & DevOps** *(planned)*
- [ ] Docker Compose setup (API + MySQL + Redis in containers)
- [ ] Dockerfile for the Spring Boot API
- [ ] Dockerfile + Nginx config for the Next.js web dashboard
- [ ] GitHub Actions CI — build, test, Docker image push
- [ ] Terraform templates for lab infrastructure (VMs, VPC, VPN)
- [ ] Ansible playbook for automated C2 server deployment
- [ ] Redirector setup guide (Apache / Nginx reverse proxy for C2 traffic)

---

## Legal Notice

This project was developed **exclusively for educational purposes, offensive security research, and controlled environment exercises** — pentest labs, Red Team operations with explicit written authorization from the infrastructure owner, and CTF competitions.

**Using this tool against systems without prior authorization is a crime**, potentially violating:
- **Brazil:** Lei nº 12.737/2012 (Lei Carolina Dieckmann) and Art. 154-A of the Penal Code
- **USA:** Computer Fraud and Abuse Act (CFAA)
- Equivalent legislation in other jurisdictions

The author **assumes no responsibility** for any misuse, illegal application, or damage caused by using this platform outside the authorized contexts described above.

---

<div align="center">

<img src="https://capsule-render.vercel.app/api?type=waving&color=0d0d0d&height=120&section=footer" />

**Zombie Keeper** — *Built for those who understand both sides of the wall.*

[![GitHub](https://img.shields.io/badge/GitHub-jtave111-181717?style=flat-square&logo=github)](https://github.com/jtave111)

</div>
