# ZombieKeeper — Estrutura do Monorepo

Este projeto é um **monorepo** contendo toda a plataforma ZombieKeeper C2: servidor API, dashboard web, arsenal de ferramentas nativas e scripts de automação.

---

## Visão Geral dos Módulos

| Módulo | Tecnologia | Porta | Status |
|---|---|---|---|
| `ZombieKeeper-Api` | Spring Boot 4 · Java 21 · MySQL 8 | 8080 | Estável |
| `ZombieKeeper-Web` | Next.js 15 · React 19 · TypeScript | 3000 | Estável |
| `ZombieKeeper-Arsenal` | C++17 · CMake · Python · Go · Rust | — | Em desenvolvimento |

---

## Layout do Repositório

```
ZombieKeeper/
│
├── ZombieKeeper-Api/                        # Servidor C2 — Spring Boot 4 · Java 21
│   ├── src/main/java/com/manager/Zombie_Keeper/
│   │   ├── controller/                      # REST: Agent, Auth, Recon
│   │   ├── service/                         # Lógica de negócio
│   │   ├── model/entity/                    # Entidades JPA
│   │   ├── model/enums/                     # Flags, Tags, Status, Severity
│   │   ├── repository/                      # Spring Data JPA
│   │   ├── dtos/                            # Request/Response DTOs
│   │   ├── configuration/security/          # Spring Security + CORS
│   │   └── util/                            # JwtUtil
│   ├── src/main/resources/
│   │   ├── application.properties           # Configuração do servidor
│   │   └── db/changelog/                    # Migrações Liquibase
│   ├── .env                                 # Variáveis de ambiente (gitignored)
│   ├── pom.xml                              # POM do módulo Maven
│   └── mvnw                                 # Maven wrapper
│
├── ZombieKeeper-Web/                        # Dashboard do Operador — Next.js 15 · React 19
│   ├── src/
│   │   ├── app/                             # Next.js App Router
│   │   ├── components/                      # Componentes React por feature
│   │   │   ├── layout/                      # App, LoginPage, Menubar, Sidebar
│   │   │   ├── agents/                      # AgentsView, AgentShell
│   │   │   ├── dashboard/                   # DashboardView, WorldMap (Leaflet)
│   │   │   ├── network/                     # NetworkView (topologia)
│   │   │   ├── scanner/                     # ScannerView
│   │   │   ├── payloads/                    # PayloadGenerator
│   │   │   ├── listeners/                   # ListenersView
│   │   │   ├── intelligence/                # CredentialsView, LootView, ReportsView
│   │   │   ├── users/                       # UsersView
│   │   │   └── shared/                      # SettingsView
│   │   ├── lib/                             # api.ts, data.ts, networkData.ts
│   │   └── styles/                          # globals.css (Tailwind + variáveis CSS)
│   ├── .env.local                           # NEXT_PUBLIC_API_URL (gitignored)
│   └── package.json
│
├── ZombieKeeper-Arsenal/                    # Arsenal de ferramentas nativas
│   │
│   ├── network-session/                     # Domínio: Blue Team — inteligência de rede
│   │   ├── scanners/
│   │   │   └── local-fingerprint/           # Fingerprint completo de subnet
│   │   │       ├── cpp/                     # Implementação C++17 (ferramenta principal)
│   │   │       │   ├── localNetwork/        # Scanner, FingerPrintSession, Models
│   │   │       │   ├── CMakeLists.txt       # Target: executável LocalFingerPrint
│   │   │       │   └── Makefile             # Wrapper de conveniência (chama cmake)
│   │   │       ├── python/                  # Scripts auxiliares HTTP
│   │   │       ├── go/                      # Implementação Go concorrente (planejado)
│   │   │       └── README.md
│   │   ├── discovery/                       # Descoberta de hosts (planejado)
│   │   │   ├── icmp-sweep/
│   │   │   ├── arp-scan/
│   │   │   └── dns-enum/
│   │   ├── osint/                           # Reconhecimento externo (planejado)
│   │   │   ├── subdomain/
│   │   │   ├── shodan/
│   │   │   └── ssl-analysis/
│   │   ├── libs/                            # Bibliotecas compartilhadas do domínio
│   │   │   └── cpp/
│   │   │       └── ping/                   # Biblioteca ICMP (usada pelo local-fingerprint)
│   │   │           └── CMakeLists.txt      # Target: lib estática libping.a
│   │   ├── CMakeLists.txt                  # Agregador do domínio network-session
│   │   └── README.md
│   │
│   ├── agents/                              # Domínio: Red Team — implants e exploits
│   │   ├── implants/                        # Beacons C2 por plataforma
│   │   │   ├── linux/
│   │   │   │   ├── cpp/                     # Implant Linux em C++ (planejado)
│   │   │   │   ├── rust/                    # Implant Linux em Rust (planejado)
│   │   │   │   └── go/                      # Implant Linux em Go (planejado)
│   │   │   ├── windows/
│   │   │   │   ├── cpp/                     # Implant Windows em C++ (planejado)
│   │   │   │   └── rust/                    # Implant Windows em Rust (planejado)
│   │   │   └── cross-platform/
│   │   │       └── go/                      # Implant multiplataforma em Go (planejado)
│   │   ├── exploits/                        # Módulos de exploração (planejado)
│   │   │   ├── linux/
│   │   │   ├── windows/
│   │   │   └── web/
│   │   ├── post-exploitation/               # Pós-acesso por plataforma (planejado)
│   │   │   ├── linux/
│   │   │   │   ├── persistence/
│   │   │   │   ├── privesc/
│   │   │   │   └── credentials/
│   │   │   └── windows/
│   │   │       ├── persistence/
│   │   │       ├── privesc/
│   │   │       └── credentials/
│   │   ├── attacks/                         # Ataques ativos por vetor (planejado)
│   │   │   ├── network/                     # ARP, DNS, wireless, BGP
│   │   │   ├── web/                         # SQLi, XSS, SSRF, JWT
│   │   │   └── credentials/                 # Brute-force, stuffing, phishing
│   │   ├── payloads/                        # Shellcodes e ROP chains (planejado)
│   │   │   ├── x86_64/asm/
│   │   │   └── arm64/asm/
│   │   ├── evasion/                         # Bypass AV/EDR, anti-forense (planejado)
│   │   │   ├── linux/
│   │   │   └── windows/
│   │   ├── hardware/                        # BadUSB, SDR, RFID (planejado)
│   │   │   ├── badusb/
│   │   │   ├── sdr/
│   │   │   └── rfid/
│   │   └── README.md
│   │
│   ├── build/                               # Artefatos de build CMake (gitignored)
│   │   └── network-session/scanners/local-fingerprint/cpp/
│   │       └── LocalFingerPrint             # Binário compilado
│   │
│   ├── scripts/                             # Automação de build e deploy
│   │   ├── build-all.sh
│   │   ├── build-network-session.sh
│   │   ├── build-agents.sh
│   │   └── clean-all.sh
│   │
│   ├── CMakeLists.txt                       # Entry point CMake (abrir no CLion)
│   ├── Makefile                             # Wrapper de conveniência sobre cmake
│   └── .gitignore
│
├── pom.xml                                  # Agregador Maven (monorepo root)
├── start.sh                                 # Script de inicialização de todos os serviços
├── README.md                                # Documentação principal do projeto
├── MONOREPO.md                              # Este arquivo
└── HELP.md                                  # Referência rápida para desenvolvedores
```

---

## Iniciando a Plataforma

### Início rápido (todos os serviços)

```bash
./start.sh
```

### Com recompilação da API

```bash
./start.sh --build
```

### Serviços individuais

```bash
# Somente API
./start.sh --api-only

# Somente dashboard web
./start.sh --web-only
```

### Manual

```bash
# API
cd ZombieKeeper-Api
./mvnw spring-boot:run
# → http://localhost:8080

# Web
cd ZombieKeeper-Web
npm run dev
# → http://localhost:3000
```

---

## Build para Produção

### API

```bash
cd ZombieKeeper-Api
./mvnw clean package -DskipTests
java -jar target/Zombie-Keeper-0.0.1-SNAPSHOT.jar
```

### Web

```bash
cd ZombieKeeper-Web
npm run build
npm start
```

### Arsenal — Ferramentas C/C++

```bash
cd ZombieKeeper-Arsenal

# Instalar dependências (primeira vez)
sudo apt install build-essential cmake libcurl4-openssl-dev

# Build completo (Debug)
make

# Build Release (otimizado para deploy)
make release

# Build de apenas uma ferramenta
cmake --build build --target LocalFingerPrint

# Aplicar capabilities de rede (necessário para rodar)
sudo cmake --build build --target setcap

# Limpar artefatos
make clean        # limpa artefatos, mantém config cmake
make reset        # remove build/ inteiro
```

O binário compilado fica em:
```
ZombieKeeper-Arsenal/build/network-session/scanners/local-fingerprint/cpp/LocalFingerPrint
```

---

## Variáveis de Ambiente

Ambos os módulos requerem seus próprios arquivos de ambiente. **Esses arquivos são gitignored — nunca commite credenciais.**

| Arquivo | Módulo | Obrigatório |
|---|---|---|
| `ZombieKeeper-Api/.env` | Servidor API | Sim |
| `ZombieKeeper-Web/.env.local` | Dashboard Web | Sim |

Veja [HELP.md](HELP.md) para a lista completa de variáveis.

---

## Agregador Maven

O `pom.xml` raiz é um **agregador puro** (`<packaging>pom</packaging>`). Ele permite executar comandos Maven a partir da raiz que se aplicam a todos os módulos Java.

```bash
# Build de todos os módulos Java a partir da raiz
./mvnw clean package -DskipTests -f pom.xml
```

`ZombieKeeper-Api` mantém o `spring-boot-starter-parent` como seu próprio parent — o POM raiz não interfere no gerenciamento de dependências do Spring Boot.

---

## Status dos Módulos

### Serviços

| Módulo | Caminho | Status |
|---|---|---|
| ZombieKeeper-Api | `ZombieKeeper-Api/` | Estável · porta 8080 |
| ZombieKeeper-Web | `ZombieKeeper-Web/` | Estável · porta 3000 |

### Arsenal — network-session (Blue Team)

| Ferramenta | Caminho | Linguagem | Status |
|---|---|---|---|
| LocalFingerPrint | `network-session/scanners/local-fingerprint/cpp/` | C++17 | Estável |
| Ping (lib) | `network-session/libs/cpp/ping/` | C++17 | Estável (lib) |
| Scripts HTTP | `network-session/scanners/local-fingerprint/python/` | Python | Parcial |
| LocalFingerPrint Go | `network-session/scanners/local-fingerprint/go/` | Go | Planejado |
| icmp-sweep | `network-session/discovery/icmp-sweep/` | — | Planejado |
| arp-scan | `network-session/discovery/arp-scan/` | — | Planejado |
| dns-enum | `network-session/discovery/dns-enum/` | — | Planejado |
| Subdomain OSINT | `network-session/osint/subdomain/` | — | Planejado |
| Shodan OSINT | `network-session/osint/shodan/` | — | Planejado |
| SSL Analysis | `network-session/osint/ssl-analysis/` | — | Planejado |

### Arsenal — agents (Red Team)

| Categoria | Caminho | Status |
|---|---|---|
| Implants Linux | `agents/implants/linux/` | Planejado |
| Implants Windows | `agents/implants/windows/` | Planejado |
| Implants Cross-Platform | `agents/implants/cross-platform/` | Planejado |
| Exploits Linux/Windows/Web | `agents/exploits/` | Planejado |
| Post-Exploitation Linux/Windows | `agents/post-exploitation/` | Planejado |
| Ataques Network/Web/Creds | `agents/attacks/` | Planejado |
| Payloads x86_64/arm64 | `agents/payloads/` | Planejado |
| Evasion Linux/Windows | `agents/evasion/` | Planejado |
| Hardware BadUSB/SDR/RFID | `agents/hardware/` | Planejado |
