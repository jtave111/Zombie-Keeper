<div align="center">

<img src="https://capsule-render.vercel.app/api?type=waving&color=0d0d0d&height=220&section=header&text=Zombie%20Keeper&fontSize=80&fontColor=ff0000&animation=fadeIn&fontAlign=50" alt="Zombie Keeper" />

# Zombie Keeper — Framework C2

**Plataforma Command & Control dual-purpose para monitoramento de infraestrutura e operações de segurança ofensiva**

[![Java](https://img.shields.io/badge/Java-21-ED8B00?style=for-the-badge&logo=openjdk&logoColor=white)](https://openjdk.org/projects/jdk/21/)
[![Spring Boot](https://img.shields.io/badge/Spring%20Boot-4.0-6DB33F?style=for-the-badge&logo=springboot&logoColor=white)](https://spring.io/projects/spring-boot)
[![Tauri](https://img.shields.io/badge/Tauri-2-24C8DB?style=for-the-badge&logo=tauri&logoColor=white)](https://tauri.app/)
[![React](https://img.shields.io/badge/React-19-61DAFB?style=for-the-badge&logo=react&logoColor=black)](https://react.dev/)
[![C++](https://img.shields.io/badge/C++17-Raw%20Sockets-00599C?style=for-the-badge&logo=cplusplus&logoColor=white)](https://isocpp.org/)
[![CMake](https://img.shields.io/badge/CMake-3.20+-064F8C?style=for-the-badge&logo=cmake&logoColor=white)](https://cmake.org/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5-3178C6?style=for-the-badge&logo=typescript&logoColor=white)](https://www.typescriptlang.org/)
[![MySQL](https://img.shields.io/badge/MySQL-8-4479A1?style=for-the-badge&logo=mysql&logoColor=white)](https://www.mysql.com/)
[![Rust](https://img.shields.io/badge/Rust-stable-000000?style=for-the-badge&logo=rust&logoColor=white)](https://www.rust-lang.org/)
[![Spring Security](https://img.shields.io/badge/Spring%20Security-JWT-4CA154?style=for-the-badge&logo=springsecurity&logoColor=white)](#)

<br/>

> ⚠️ **APENAS PARA USO AUTORIZADO** — Laboratórios de pentest, operações Red Team com autorização escrita, competições CTF e pesquisa de segurança ofensiva. Uso não autorizado é ilegal. Leia o [Aviso Legal](#-aviso-legal).

</div>

---

## Índice

- [Visão Geral](#-visão-geral)
- [Arquitetura](#-arquitetura)
- [Módulos](#-módulos)
  - [ZombieKeeper-Api — Servidor C2 Spring Boot](#zombiekeeper-api--servidor-c2-spring-boot)
  - [ZombieKeeper-Client — Desktop App (Tauri)](#zombiekeeper-client--desktop-app-tauri)
  - [ZombieKeeper-Arsenal — Network Session (Blue Team)](#zombiekeeper-arsenal--network-session-blue-team)
  - [ZombieKeeper-Arsenal — Agents (Red Team)](#zombiekeeper-arsenal--agents-red-team)
- [Stack Tecnológica](#-stack-tecnológica)
- [Estrutura do Projeto](#-estrutura-do-projeto)
- [Instalação e Configuração](#-instalação-e-configuração)
- [Uso](#-uso)
- [Roadmap](#-roadmap)
- [Aviso Legal](#-aviso-legal)

---

## Visão Geral

**Zombie Keeper** é uma plataforma **Command & Control (C2)** full-stack construída do zero para aprendizado de segurança ofensiva e operações Red/Blue Team em ambientes controlados.

O sistema opera em três camadas principais:

- **Servidor C2** (`ZombieKeeper-Api`) — API REST Spring Boot 4 que orquestra agents, recebe telemetria de rede, gerencia sessões e autentica operadores via JWT.
- **Desktop App** (`ZombieKeeper-Client`) — Aplicação desktop Tauri 2 (Rust + Vite + React 19) para interação do operador: gerenciamento de agents, acesso shell, topologia de rede, geração de payloads e administração de usuários. Roda em Linux, Windows e macOS.
- **Arsenal** (`ZombieKeeper-Arsenal`) — Coleção de ferramentas nativas dividida em dois domínios:
  - **network-session** (Blue Team): scanner C++17 com Raw Sockets para fingerprint de rede local, descoberta ICMP e scan TCP, reportando resultados ao servidor C2.
  - **agents** (Red Team): implants, exploits, módulos de pós-exploração e ferramentas de ataque (em desenvolvimento).

---

## Arquitetura

```
┌─────────────────────────────────────────────────────────────────┐
│                    ZombieKeeper-Client                            │
│           Tauri 2 · Vite · React 19 · TypeScript                 │
│                                                                  │
│  Dashboard · Agents · Shell · Network · Payloads                 │
│  Listeners · Scanner · Credentials · Users · Settings            │
└────────────────────────┬─────────────────────────────────────────┘
                         │ HTTP/REST direto (JWT Bearer no header)
                         │ WebSocket ws://localhost:8080/term?token=JWT
┌────────────────────────▼─────────────────────────────────────────┐
│                      ZombieKeeper-Api                             │
│                Spring Boot 4 · Java 21 · MySQL 8                 │
│                                                                  │
│  ┌──────────────────┐  ┌──────────────────┐  ┌───────────────┐  │
│  │  REST Controllers│  │  Camada de Serviço│  │  Segurança    │  │
│  │                  │  │                  │  │               │  │
│  │  AgentRest       │  │  AgentsService   │  │  Spring       │  │
│  │  AuthRest        │  │  AuthService     │  │  Security     │  │
│  │  ReconRest       │  │  FingerprintSvc  │  │  JWT · Roles  │  │
│  └────────┬─────────┘  │  ProcessMgrSvc   │  └───────────────┘  │
│           │ JPA        │  AgentLocationSvc│                      │
│  ┌────────▼──────────────────────────────────────────────────┐   │
│  │                 Modelo de Dados (JPA / MySQL)              │   │
│  │                                                           │   │
│  │  ┌─────────────────────┐   ┌───────────────────────────┐ │   │
│  │  │  Domínio Red Team   │   │  Domínio Blue Team        │ │   │
│  │  │                     │   │                           │ │   │
│  │  │  Agent              │   │  NetworkSession           │ │   │
│  │  │  └── Loot           │   │  └── NetworkNode          │ │   │
│  │  │  AgentLocation      │   │      └── Port             │ │   │
│  │  │                     │   │          └── Vulnerability│ │   │
│  │  └─────────────────────┘   └───────────────────────────┘ │   │
│  │  User · Role                                              │   │
│  └───────────────────────────────────────────────────────────┘   │
└─────────────────┬──────────────────────┬────────────────────────┘
                  │ HTTP POST            │ ProcessBuilder
          (resultados do scan)    (execução do binário)
              ┌───▼──────────────────────▼───┐
              │    ZombieKeeper-Arsenal       │
              │                              │
              │  ┌─────────────────────────┐ │
              │  │  libs/cpp/              │ │   ← libs compartilhadas
              │  │    net_utils/           │ │     checksum ICMP (in_cksum)
              │  │      checksum/          │ │
              │  │      ping/              │ │     raw ICMP (linka net_utils)
              │  │    output_utils/        │ │     ZKOutput + JsonSerializer
              │  │                         │ │     nlohmann/json FetchContent
              │  │  network-session/tools/ │ │   ← Blue Team
              │  │    local-fingerprint/   │ │
              │  │      include/  src/     │ │
              │  │      ICMP sweep         │ │
              │  │      TCP port scan      │ │
              │  │      Node · Port · Vuln │ │
              │  └─────────────────────────┘ │
              │  ┌─────────────────────────┐ │
              │  │  agents/               │ │   ← Red Team (planejado)
              │  │    attacks/network/dos/ │ │     TCP/ICMP flood (D_DOS)
              │  │  implants/             │ │
              │  │  exploits/             │ │
              │  │  post-exploitation/    │ │
              │  └─────────────────────────┘ │
              └──────────────────────────────┘
```

---

## Módulos

### ZombieKeeper-Api — Servidor C2 Spring Boot

O núcleo da plataforma. Construído com **Spring Boot 4 + Java 21**, expõe uma API REST completa consumida pelo dashboard web e pelos agents.

#### Controllers REST

| Controller | Caminho | Responsabilidade |
|---|---|---|
| `AgentRestController` | `/api/c2-server/agents/**` | Registro, listagem, status, ping e remoção de agents |
| `AuthRestController` | `/api/auth/**` | Login, gerenciamento de usuários e roles |
| `ReconRestController` | `/api/recon/**` | Recebe dados de scan de rede do agente C++ |

#### Modelo de Dados

```
# Domínio Red Team
Agent           → host comprometido (Zombie) com status, flags, tags, geolocalização
  └── Loot      → arquivos e credenciais extraídos do agent

# Domínio Blue Team
NetworkSession  → sessão completa de fingerprint de uma subnet
  └── NetworkNode     → host descoberto no scan
        └── Port      → porta aberta identificada no host
              └── Vulnerability → fraqueza mapeada à porta/serviço

# Autenticação
User  → operador da plataforma
  └── Role → permissão de acesso (ADMIN / OPERATOR)

# Enumeradores
Flags         → comportamento do agent (HIGH_VALUE, PIVOT, BURNED, WATCH...)
Tags          → categorização (WINDOWS, LINUX, SERVER, ROUTER, GATEWAY...)
StatusAgent   → ONLINE / OFFLINE / IDLE
SeverityLevel → LOW / MEDIUM / HIGH / CRITICAL
LocationSource → IP_API / MANUAL / AGENT_REPORTED
```

#### Serviços

| Serviço | Responsabilidade |
|---|---|
| `AgentsService` | Ciclo de vida do agent: registro, atualizações de status, recuperação de loot |
| `AuthService` | Autenticação de operadores com Spring Security + JWT + Roles |
| `AgentLocationService` | Rastreamento e enriquecimento de geolocalização dos agents |
| `LocalNetworkFingerprintService` | Orquestra a execução do agente C++ e processa os resultados de scan |
| `LocalNetworkDatabaseManagerService` | Persiste dados do scan de rede (Nodes, Ports, Vulnerabilities) |
| `ProcessManagerService` | Gerencia execução de processos externos via `ProcessBuilder` |

#### Segurança

- **JWT** — autenticação stateless com expiração configurável
- **Spring Security** — proteção de rotas com controle de acesso baseado em roles
- **CORS** — configurado para origens Tauri (`tauri://localhost`, `https://tauri.localhost`) e Vite dev (`http://localhost:1420`)
- **Bcrypt** — hash de senhas com fator de custo configurável

---

### ZombieKeeper-Client — Desktop App (Tauri)

Aplicação desktop para operadores construída com **Tauri 2 + Vite + React 19 + TypeScript + Tailwind CSS**. Compila para Linux, Windows e macOS a partir do mesmo código-fonte.

#### Views

| View | Descrição | Status |
|---|---|---|
| **Dashboard** | Painel de estatísticas com contador de agents e mapa mundial | Funcional |
| **Agents** | Tabela de agents com filtros, status e painel de detalhes | Funcional |
| **Shell** | Terminal interativo por agent | UI pronta, backend pendente |
| **Network** | Topologia da rede descoberta pelo scanner | Aguardando endpoint de sessões |
| **Scanner** | Disparar e monitorar sessões de fingerprint de rede | UI pronta, execução simulada |
| **Payloads** | Gerador de payloads para deploy de agents | UI pronta, geração fake |
| **Listeners** | Gerenciamento de listeners C2 | Placeholder |
| **Credentials** | Base de credenciais extraídas | Placeholder |
| **Loot** | Visualizador de dados exfiltrados | Placeholder |
| **Reports** | Construtor de relatórios | UI pronta, exportação pendente |
| **Users** | Gerenciamento de operadores (somente ADMIN) | Funcional (API real) |
| **Settings** | Configuração da plataforma | UI pronta, sem persistência |

#### Detalhes de Implementação

- Todas as chamadas à API centralizadas em `src/lib/client/api.ts` com injeção automática do JWT
- Token armazenado em `localStorage` (`zk_token`) — seguro em Tauri, sem acesso externo ao webview
- Lista de agents atualizada a cada 30 segundos via `setInterval`
- Mapa mundial usa Leaflet com lazy loading via `React.lazy + Suspense`
- URLs configuradas via `VITE_API_URL` e `VITE_WS_URL` (padrão: `http://localhost:8080`)
- WebSocket do shell conecta diretamente ao Spring Boot com JWT na query string
- Auth event: `zk:logout` dispara logout em qualquer componente sem prop drilling

---

### ZombieKeeper-Arsenal — Network Session (Blue Team)

Ferramentas para descoberta, fingerprint e inteligência de rede local. Os dados gerados alimentam o modelo `NetworkSession → NetworkNode → Port → Vulnerability` no servidor C2.

#### Estrutura do Arsenal

```
ZombieKeeper-Arsenal/
├── libs/
│   └── cpp/
│       ├── net_utils/               # Utilitários de rede compartilhados
│       │   ├── checksum/include/    # net_utils::icmp_checksum (in_cksum)
│       │   ├── checksum/src/
│       │   └── ping/                # ICMP raw socket — target CMake: ping
│       │       ├── include/
│       │       └── src/
│       └── output_utils/            # Saída estruturada + serialização JSON
│           ├── include/             # ZKOutput (stderr), JsonSerializer (Port/Node)
│           └── src/                 # nlohmann/json via FetchContent
│
├── network-session/
│   └── tools/
│       └── local-fingerprint/       # Scanner de rede local (C++17)
│           ├── include/             # Headers públicos + modelos
│           ├── src/                 # Implementações
│           └── CMakeLists.txt       # Target: LocalFingerPrint
│
└── agents/
    └── attacks/
        └── network/
            └── dos/                 # TCP SYN flood + ICMP/UDP flood (D_DOS)
                ├── include/
                └── src/
```

Convenção em todo o Arsenal: `include/` para headers, `src/` para `.cpp`. Todas as libs linkam `net_utils` via `target_link_libraries(... PRIVATE net_utils)`.

#### local-fingerprint (C++17)

Binário nativo compilado em **C++17** com **POSIX Raw Sockets**. Invocado pelo servidor via `ProcessManagerService` ou executado manualmente.

**Fluxo de execução:**

```
LocalFingerPrint
  ├─► ICMP sweep (ping/)         — descobre hosts ativos na subnet
  ├─► TCP port scan              — raw socket SYN scan nos hosts ativos
  ├─► Node → Port → Vuln         — constrói modelo de dados da sessão
  └─► JSON → stdout              — API Spring Boot lê via ProcessBuilder
```

Saída de progresso vai para **stderr**, JSON puro para **stdout** (necessário para integração Java via `extractJson()`).

**Exige root ou `CAP_NET_RAW`** (Raw Sockets requerem privilégio elevado).

**Sistema de build — CMake:**

```
ZombieKeeper-Arsenal/
├── Makefile                         ← wrapper: make network-session
├── libs/CMakeLists.txt
│   └── libs/cpp/CMakeLists.txt
│       ├── add_subdirectory(net_utils)        → target: net_utils
│       ├── add_subdirectory(net_utils/ping)   → target: ping (linka net_utils)
│       ├── add_subdirectory(output_utils)     → target: output_utils
│       └── FetchContent: nlohmann/json 3.11.3
│
├── network-session/CMakeLists.txt
│   └── tools/local-fingerprint/CMakeLists.txt → target: LocalFingerPrint
│
└── agents/attacks/network/dos/CMakeLists.txt  → target: dos (linka net_utils)

build/                               ← artefatos gerados (gitignored)
```

---

### ZombieKeeper-Arsenal — Agents (Red Team)

Domínio em desenvolvimento. Estrutura preparada para escalar para centenas de ferramentas organizadas por fase de ataque e plataforma.

```
agents/
├── implants/         # Beacons C2 por plataforma (linux, windows, cross-platform)
├── exploits/         # Módulos de exploração (linux, windows, web)
├── post-exploitation/# Pós-acesso (persistence, privesc, credentials)
├── attacks/          # Ataques ativos (network, web, credentials)
├── payloads/         # Shellcodes e ROP chains (x86_64, arm64)
├── evasion/          # Bypass AV/EDR, anti-forense
└── hardware/         # BadUSB, SDR, RFID
```

---

## Stack Tecnológica

| Componente | Tecnologia |
|---|---|
| Servidor C2 (API) | Java 21 + Spring Boot 4.0 |
| ORM / Persistência | Spring Data JPA + Hibernate + Liquibase |
| Banco de Dados | MySQL 8 |
| Autenticação | Spring Security + JWT + Roles |
| API REST | Spring Web MVC + Jackson |
| Desktop App | Tauri 2 + Vite + React 19 + TypeScript |
| Estilização UI | Tailwind CSS + variáveis CSS customizadas |
| Mapa | Leaflet + Leaflet.markercluster |
| Scanner de Rede | C++17 + Raw Sockets (POSIX / Linux) |
| Build (API) | Apache Maven 3 (wrapper mvnw) |
| Build (Arsenal C++) | CMake 3.20+ + GNU Make (wrapper) |
| Build (Desktop) | Rust + cargo + npm / Tauri CLI |
| Automação | Python 3 |

---

## Estrutura do Projeto

```
ZombieKeeper/
│
├── ZombieKeeper-Api/                          # Servidor C2 — Spring Boot
│   ├── src/main/java/com/manager/Zombie_Keeper/
│   │   ├── controller/                        # REST: Agent, Auth, Recon
│   │   ├── service/                           # Agents, Auth, Fingerprint, ProcessMgr, Location
│   │   ├── model/entity/                      # JPA: Agent, Loot, NetworkNode, Port, Vulnerability...
│   │   ├── model/enums/                       # Flags, Tags, StatusAgent, SeverityLevel
│   │   ├── repository/                        # Spring Data JPA
│   │   ├── dtos/                              # Request/Response DTOs
│   │   ├── configuration/security/            # SecurityConfig + CorsConfig
│   │   ├── util/                              # JwtUtil
│   │   └── exception/                         # DuplicateAgentException
│   ├── src/main/resources/
│   │   ├── application.properties             # Configuração do servidor
│   │   └── db/changelog/                      # Migrações Liquibase
│   ├── .env                                   # Variáveis de ambiente (gitignored)
│   └── pom.xml
│
├── ZombieKeeper-Client/                       # Desktop App — Tauri 2 + Vite + React
│   ├── src/
│   │   ├── main.tsx                           # Entrypoint React (monta Root)
│   │   ├── Root.tsx                           # Auth gate: LoginPage ou App
│   │   ├── components/                        # Componentes React por feature
│   │   │   ├── layout/                        # App (roteamento), LoginPage, Menubar, Sidebar
│   │   │   ├── agents/                        # AgentsView, AgentShell, AgentTableHeader
│   │   │   ├── dashboard/                     # DashboardView, WorldMap
│   │   │   ├── network/                       # NetworkView
│   │   │   ├── scanner/                       # ScannerView
│   │   │   ├── payloads/                      # PayloadGenerator
│   │   │   ├── listeners/                     # ListenersView
│   │   │   ├── intelligence/                  # CredentialsView, LootView, ReportsView
│   │   │   ├── users/                         # UsersView
│   │   │   └── shared/                        # SettingsView
│   │   └── lib/
│   │       ├── client/api.ts                  # HTTP + WebSocket: req(), auth, shellWsUrl()
│   │       ├── dtos/                          # Tipos espelho do Spring Boot
│   │       └── models/                        # Tipos internos do frontend
│   ├── src-tauri/                             # Core Rust (Tauri)
│   │   ├── src/lib.rs                         # Ponto de entrada Tauri
│   │   ├── Cargo.toml
│   │   └── tauri.conf.json                    # Produto: nome, janela, URLs
│   ├── vite.config.ts                         # Vite: alias @/, port 1420
│   ├── .env                                   # VITE_API_URL, VITE_WS_URL (gitignored)
│   └── package.json
│
├── ZombieKeeper-Arsenal/                      # Arsenal de ferramentas nativas
│   │
│   ├── libs/cpp/                              # Bibliotecas compartilhadas C++17
│   │   ├── net_utils/checksum/include/ src/   # ICMP checksum (in_cksum)
│   │   ├── net_utils/ping/include/ src/       # Raw ICMP socket (linka net_utils)
│   │   └── output_utils/include/ src/         # ZKOutput + JsonSerializer (nlohmann/json)
│   │
│   ├── network-session/                       # Domínio: Blue Team
│   │   └── tools/local-fingerprint/
│   │       ├── include/                       # Headers públicos do scanner
│   │       ├── src/                           # Implementação C++17
│   │       └── CMakeLists.txt                 # Target: LocalFingerPrint
│   │
│   ├── agents/                                # Domínio: Red Team
│   │   ├── attacks/network/dos/               # TCP SYN flood + ICMP/UDP flood (D_DOS)
│   │   ├── implants/linux/    (cpp, rust, go) # Beacons Linux (planejado)
│   │   ├── implants/windows/  (cpp, rust)     # Beacons Windows (planejado)
│   │   ├── exploits/          (linux, windows, web)
│   │   ├── post-exploitation/ (linux, windows)
│   │   ├── attacks/           (network, web, credentials)
│   │   ├── payloads/          (x86_64/asm, arm64/asm)
│   │   ├── evasion/           (linux, windows)
│   │   └── hardware/          (badusb, sdr, rfid)
│   │
│   ├── Makefile                               # make network-session / make all
│   └── .gitignore
│
├── pom.xml                                    # Agregador Maven (monorepo root)
├── ZombieKeeper.sh                            # Script de inicialização da plataforma
├── README.md                                  # Este arquivo
├── MONOREPO.md                                # Estrutura detalhada do monorepo
└── HELP.md                                    # Referência rápida para desenvolvedores
```

---

## Instalação e Configuração

### Pré-requisitos

| Ferramenta | Versão | Finalidade |
|---|---|---|
| Java (JDK) | 21+ | Servidor C2 (API) |
| Maven | 3.8+ | Build da API (ou use o wrapper `mvnw`) |
| Node.js | 20+ | Cliente desktop (Tauri) |
| Rust (cargo) | stable | Cliente desktop (Tauri core) |
| MySQL | 8+ | Banco de dados |
| GCC / G++ | 11+ com C++17 | Arsenal C++ |
| CMake | 3.20+ | Sistema de build do Arsenal |
| libcurl-dev | qualquer | Dependência do scanner C++ |
| Python | 3.10+ | Scripts de automação |

> Raw Sockets exigem **root ou `CAP_NET_RAW`** no host que executa o scanner.

---

### 1. Clonar o repositório

```bash
git clone https://github.com/jtave111/Zombie-Keeper.git
cd Zombie-Keeper
```

### 2. Configurar variáveis de ambiente

```bash
# Configurar o arquivo de ambiente da API
cp ZombieKeeper-Api/.env.example ZombieKeeper-Api/.env
nano ZombieKeeper-Api/.env

```

**Variáveis mínimas obrigatórias em `ZombieKeeper-Api/.env`:**

```env
DB_HOST=localhost
DB_PORT=3306
DB_NAME=c2_db
DB_USERNAME=seu_usuario_db
DB_PASSWORD=sua_senha_db
JWT_SECRET=sua-chave-secreta-com-minimo-32-caracteres
ADMIN_USERNAME=admin
ADMIN_PASSWORD=SuaSenhaSegura!
```

**Variáveis do cliente desktop em `ZombieKeeper-Client/.env`:**

```env
VITE_API_URL=http://localhost:8080
VITE_WS_URL=ws://localhost:8080
```

### 3. Iniciar todos os serviços (recomendado)

```bash
# Iniciar API + cliente desktop (Tauri dev)
./ZombieKeeper.sh

# Compilar a API primeiro e depois iniciar tudo
./ZombieKeeper.sh --build

# Iniciar somente a API
./ZombieKeeper.sh --api-only

# Iniciar somente o cliente desktop
./ZombieKeeper.sh --client
```

### 4. Inicialização manual

**Servidor API:**
```bash
cd ZombieKeeper-Api
./mvnw spring-boot:run
# API disponível em http://localhost:8080
```

**Cliente desktop:**
```bash
cd ZombieKeeper-Client
npm install
npm run tauri dev
# A janela do aplicativo é aberta automaticamente
```

### 5. Compilar o Arsenal C++ (Linux)

```bash
# Instalar dependências (Arch)
sudo pacman -S cmake gcc

# Instalar dependências (Debian/Ubuntu)
sudo apt install build-essential cmake

cd ZombieKeeper-Arsenal

# Build do scanner de rede local
make network-session
```

**Aplicar capabilities de rede** (necessário para raw sockets sem root):
```bash
sudo setcap cap_net_raw+ep build/network-session/tools/local-fingerprint/LocalFingerPrint
```

**Executar o scanner:**
```bash
./build/network-session/tools/local-fingerprint/LocalFingerPrint --create_session -all-ports 60 0
```

**Usar no CLion:**
```
File → Open → selecionar ZombieKeeper-Arsenal/
CLion detecta o CMakeLists.txt raiz automaticamente.
Targets disponíveis: LocalFingerPrint · ping · D_DOS · net_utils
```

---

## Uso

### Fluxo do Operador

**1. Login** — Abra o aplicativo ZombieKeeper (ou execute `./ZombieKeeper.sh`) e autentique-se com suas credenciais de operador.

**2. Dashboard** — Painel de visão geral com contador de agents ativos e mapa mundial com geolocalizações.

**3. Agents** — Tabela completa de agents com status (`ONLINE` / `OFFLINE` / `IDLE`), flags, tags e última visualização. Clique duplo em um agent para abrir o shell.

**4. Shell** — Interface de comando interativo para um agent ativo.

**5. Scanner** — Disparar uma sessão de fingerprint de rede local. O servidor invoca o binário C++ no host alvo, que escaneia a subnet e reporta os resultados.

**6. Network** — Visualizar a topologia descoberta: hosts, portas abertas e vulnerabilidades mapeadas com níveis de severidade.

**7. Payloads** — Gerar payloads de deploy para novos agents.

**8. Users** — (somente ADMIN) Criar, atualizar e remover contas de operadores e gerenciar atribuições de roles.

---

## Roadmap

> Legenda: **[x]** Concluído · **[~]** Em Progresso (UI pronta, backend pendente) · **[ ]** Planejado

---

**Servidor C2 (API)**
- [x] API REST Spring Boot 4 + Spring Security + JWT + Roles
- [x] Modelo de dados completo: Agent, Loot, NetworkSession, NetworkNode, Port, Vulnerability
- [x] Rastreamento de geolocalização de agents (`AgentLocation` + `AgentLocationService`)
- [x] `ProcessManagerService` para execução de binários externos
- [x] Migrações de banco com Liquibase
- [x] Configuração CORS + segurança para o frontend web
- [ ] `GET /api/c2-server/sessions` — endpoint de listagem de sessões de rede
- [ ] Canal WebSocket para comunicação em tempo real agent ↔ servidor
- [ ] Loot: endpoints de upload, armazenamento e download de arquivos
- [ ] API de gerenciamento de listeners (criar, listar, parar)
- [ ] API de armazenamento e recuperação de credenciais
- [ ] Geração de relatórios de sessão (exportação PDF / JSON)
- [ ] API de persistência de configurações (parâmetros do servidor C2)
- [ ] Integração com MITRE ATT&CK Navigator
- [ ] Correlação automática de CVEs via NVD API

---

**Desktop App (Cliente Tauri)**
- [x] UI dark terminal com navegação completa de operador (12 views)
- [x] Login com autenticação JWT + persistência via validação de expiração client-side (sem logout falso em restart)
- [x] Login page com tema IDE dark consistente e monitor de latência de API pré-autenticação
- [x] ErrorBoundary em Root — crashes de render exibem erro legível em vez de tela preta
- [x] Dashboard com estatísticas de agents em tempo real e mapa mundial Leaflet
- [x] Tabela de agents — API real, filtros, busca, ação de kill
- [x] Gerenciamento de usuários — CRUD completo com atribuição de roles (API real)
- [x] Design system coeso: tema dark terminal consistente em todas as 12 views (token CSS + PayloadGenerator como referência visual)
- [~] Shell do agent — UI terminal pronta, WebSocket direto ao Spring Boot (precisa de backend real)
- [~] Tabs do Shell — Process List, File Manager, Port Forward, Sysinfo (UI pronta, sem backend)
- [~] View Scanner — UI + construtor de comandos pronto, execução de scan simulada
- [~] Gerador de Payloads — UI de configuração completa, output de build falso (sem geração real)
- [~] View de Topologia de Rede — UI pronta, aguardando endpoint `GET /api/c2-server/sessions`
- [~] Construtor de Relatórios — seletor de seções e formato pronto, sem geração real
- [~] Settings — todas as tabs UI completas, sem persistência (botões save/test não funcionais)
- [ ] View Listeners — integração com backend (UI é placeholder vazio)
- [ ] View Credentials — integração com backend (UI é placeholder vazio)
- [ ] Navegador de arquivos Loot, preview e download
- [ ] Feed do operador em tempo real via WebSocket
- [ ] Grafo de topologia de rede (D3.js ou vis.js)
- [ ] Shell — execução real de comandos encaminhada ao agent
- [ ] Download de payload após geração
- [ ] Exportação de relatório (PDF / HTML)
- [ ] Build de produção Tauri (`.deb`, `.AppImage`, `.exe`, `.dmg`)
- [ ] Atualização automática via Tauri updater

---

**Arsenal — network-session · Scanner C++ (Linux)**
- [x] ICMP sweep para descoberta de hosts (`Ping.cpp` — lib estática `libping.a`)
- [x] Scanner TCP de portas via Raw Sockets (`Scanner.cpp`)
- [x] Modelo de sessão: Node → Port → Vulnerability
- [x] Serialização da sessão e HTTP POST para o servidor C2
- [x] Build via CMake 3.20+ com suporte a CLion
- [x] Biblioteca Ping isolada como target CMake independente (dentro de net_utils)
- [x] Target `setcap` para aplicação de capabilities sem bloquear o build
- [x] `output_utils` — ZKOutput (log estruturado stderr/stdout) + JsonSerializer (Port, Node → JSON)
- [x] nlohmann/json v3.11.3 via CMake FetchContent (portabilidade, sem git submodule)
- [x] D_DOS movido para `agents/attacks/network/dos/` (separação Blue/Red Team)
- [ ] Banner grabbing de serviços (identificar versões de serviços em portas abertas)
- [ ] OS fingerprinting via TTL / análise de TCP stack
- [ ] Keep-alive beacon com intervalo de check-in configurável
- [ ] Canal C2 bidirecional (receber e executar comandos do servidor)
- [ ] Módulo de exfiltração de arquivos (ler + HTTP POST como loot)
- [ ] Correlação automática de CVEs para versões de serviços descobertas
- [ ] Pós-exploração: verificações de escalonamento de privilégio
- [ ] Pós-exploração: mecanismos de persistência (cron, systemd)

---

**Arsenal — network-session · Scanner Go (Linux)**
- [ ] Implementação concorrente de alta performance via goroutine pool
- [ ] Mesma interface de output JSON que a versão C++

---

**Arsenal — network-session · Discovery**
- [ ] `icmp-sweep` — varredura ICMP standalone
- [ ] `arp-scan` — descoberta via ARP (camada 2)
- [ ] `dns-enum` — enumeração DNS (registros, zona transfer, brute-force)

---

**Arsenal — network-session · OSINT**
- [ ] Enumeração de subdomínios (brute-force + certificate transparency logs)
- [ ] Tentativa de transferência de zona DNS + enumeração
- [ ] Lookup WHOIS / ASN e mapeamento de ranges de IP
- [ ] Integração com API Shodan — descoberta passiva de hosts
- [ ] Fingerprinting de aplicações web (detecção de stack tecnológico)
- [ ] Brute-force de diretórios e arquivos (estilo gobuster)
- [ ] Análise de certificados SSL/TLS e detecção de misconfigurações

---

**Arsenal — agents · Implants Linux**
- [ ] Beacon C2 em C++ (keep-alive, execução de comandos)
- [ ] Beacon C2 em Rust — footprint mínimo, sem dependências de runtime
- [ ] Beacon C2 em Go — cross-compile para Linux/Windows/macOS

---

**Arsenal — agents · Implants Windows**
- [ ] Port WinSock2 do scanner de rede
- [ ] Enumeração de serviços Windows
- [ ] Build via MSVC / CMake
- [ ] Process hollowing — substituir memória de processo legítimo
- [ ] DLL injection via `CreateRemoteThread` + `LoadLibrary`
- [ ] DLL injection reflexiva (sem escrita em disco, apenas em memória)
- [ ] Token impersonation — roubar tokens de processos com alto privilégio
- [ ] Técnicas de bypass de UAC (fodhelper, CMSTPLUA, etc.)
- [ ] Persistência: Registry (`Run` keys, instalação de serviço)
- [ ] Persistência: Scheduled Tasks via COM (`ITaskService`)
- [ ] Persistência: WMI event subscription
- [ ] Dump de credenciais do LSASS (estilo Mimikatz, em memória)
- [ ] Extração de hashes SAM / NTDS
- [ ] Patching de ETW (Event Tracing for Windows) para cegar defensores
- [ ] Técnicas de bypass de AMSI (patching de `amsi.dll` em memória)
- [ ] Abuso de exclusão de caminhos do Windows Defender

---

**Arsenal — agents · Módulos Go**
- [ ] Beacon / implant em Go — cross-compile para Linux / Windows / macOS
- [ ] Comms C2 HTTP/S com TLS + certificate pinning
- [ ] Autenticação mTLS mútua entre agent e servidor
- [ ] Canal C2 encoberto via DNS-over-HTTPS (DoH)
- [ ] Domain fronting via headers CDN
- [ ] Ofuscação de tráfego — C2 HTTP disfarçado como navegação legítima
- [ ] Execução de payload em memória (sem escrita em disco, `memfd_create` no Linux)
- [ ] Pivoting via proxy SOCKS5 através de host comprometido
- [ ] Port forwarding / reverse tunnel via SSH ou TCP raw
- [ ] Implant Go com staged payload (stager → agent completo)
- [ ] Injeção de processo via `ptrace` (Linux) / `NtWriteVirtualMemory` (Windows)
- [ ] Packer ELF / PE para reduzir assinaturas binárias
- [ ] Gerador de stub polimórfico (randomizar layout binário por build)

---

**Arsenal — agents · Módulos Rust**
- [ ] Scanner de rede memory-safe (substitui o C++ a longo prazo)
- [ ] Implant Rust — footprint mínimo, sem dependências de runtime
- [ ] Módulos compatíveis com BOF (Beacon Object File)
- [ ] Dropper de payload encriptado
- [ ] Verificações anti-debug e anti-sandbox
- [ ] Stack TLS customizada com evasão de fingerprint de tráfego
- [ ] Protótipo de módulo de kernel / rootkit (Linux LKM, somente em lab)

---

**Arsenal — agents · PowerShell / .NET**
- [ ] Agent PowerShell — executa inteiramente em memória (`IEX` / `Invoke-Expression`)
- [ ] One-liners de bypass AMSI em PowerShell (referência de lab)
- [ ] Agent .NET (C#) usando `System.Reflection` para carregamento de assembly em memória
- [ ] Enumeração AD estilo BloodHound (usuários, grupos, ACLs, GPOs)
- [ ] Kerberoasting — enumeração de SPN + extração de tickets TGS
- [ ] AS-REP Roasting — atacar contas com pré-autenticação desabilitada
- [ ] Pass-the-Hash via wrapper `sekurlsa::pth`
- [ ] Pass-the-Ticket (importar tickets Kerberos forjados)
- [ ] Ataque DCSync — simular replicação de controlador de domínio para dump de hashes
- [ ] Enumeração LDAP (usuários, computadores, trusts, informações de domínio)
- [ ] Enumeração SMB (shares, sessões, usuários via NetAPI)

---

**Arsenal — agents · Assembly / Shellcode / Desenvolvimento de Exploits**
- [ ] Stubs de shellcode x86-64 — Linux `execve("/bin/sh")` via syscalls raw
- [ ] Stubs de shellcode x86-64 — Windows `WinExec` / reverse shell via WinSock2
- [ ] Shellcode position-independent (PIC) — sem endereços hardcoded
- [ ] Loader de shellcode staged (stager baixa e executa segundo estágio)
- [ ] Shellcode encriptado XOR / AES com stub de decriptação em runtime
- [ ] Templates de exploit buffer overflow baseado em stack (ret2win, ret2libc)
- [ ] Helpers de construção de cadeia ret2syscall
- [ ] Integração com finder de gadgets ROP (ROPgadget / ropper)
- [ ] Construtor de cadeia ROP para bypass de NX/DEP
- [ ] SROP — template de exploit Sigreturn-Oriented Programming
- [ ] Templates de exploit format string (`%n` write-what-where)
- [ ] Templates de heap exploitation — tcache poisoning, fastbin dup
- [ ] Template de exploit Use-After-Free (UAF)
- [ ] Template de exploit integer overflow → heap overflow
- [ ] Template de exploit type confusion (hijack de vtable C++)
- [ ] ELF injection — injeção de código parasita em binários existentes
- [ ] PE injection — injetar código em headers PE Windows
- [ ] Técnicas de leak de ASLR (format string, partial overwrite)
- [ ] Templates de exploit de kernel (somente em VMs de lab): `commit_creds` ret2user, dirty pipe

---

**Arsenal — agents · Ataques de Rede**
- [ ] ARP spoofing + interceptor de tráfego MITM (`scapy`)
- [ ] DNS spoofing — interceptar e forjar respostas DNS na LAN
- [ ] DHCP starvation + servidor DHCP rogue (redirecionar gateway padrão)
- [ ] Ataque de redirecionamento ICMP para hijack de tabelas de roteamento
- [ ] TCP session hijacking (injeção RST, predição de sequência)
- [ ] SSL stripping — downgrade HTTPS para HTTP em posição MITM
- [ ] LLMNR / NBT-NS / mDNS poisoning (estilo Responder)
- [ ] SYN flood com IPs de origem randomizados (raw socket)
- [ ] Wi-Fi deauthentication (injeção de frame de gerenciamento IEEE 802.11)
- [ ] Captura de handshake WPA2 4-way + crack offline (integração hashcat)
- [ ] Ataque PMKID (crack WPA2 sem cliente)
- [ ] Evil Twin AP — ponto de acesso rogue com portal cativo

---

**Arsenal — agents · Ataques Web**
- [ ] Fuzzer de SQL injection com detecção blind / time-based
- [ ] Injetor de payload XSS e scanner de reflexão
- [ ] Probe SSRF — descoberta de rede interna via parâmetro vulnerável
- [ ] Testador de injeção XXE (leitura de arquivo + SSRF via parser XML)
- [ ] Detecção de SSTI (Server-Side Template Injection — Jinja2, Twig, Freemarker)
- [ ] Fuzzer de directory/path traversal
- [ ] Toolkit de adulteração JWT (algoritmo none, RS256→HS256, força bruta de segredos fracos)
- [ ] Scanner de misconfigurações CORS
- [ ] Probe de HTTP request smuggling (CL.TE / TE.CL)

---

**Arsenal — agents · Pós-Exploração**
- [ ] Captura de screenshot (X11 / Win32 GDI)
- [ ] Módulo keylogger (X11 `XRecord` / Win32 `SetWindowsHookEx`)
- [ ] Monitor e exfiltrador de clipboard
- [ ] Extração de credenciais de browser (Chromium SQLite, Firefox key4.db)
- [ ] Coleta de SSH known_hosts e chaves privadas
- [ ] Scanning de variáveis de ambiente e secrets (`.env`, chaves AWS, tokens)
- [ ] Abuso de Docker socket para escape de container
- [ ] Checker de misconfigurações sudo (estilo GTFOBins)
- [ ] Enumeração de binários SUID/SGID
- [ ] Scanner de oportunidades de hijacking de cron jobs
- [ ] Scraping de memória `/proc` para credenciais em processos em execução

---

**Arsenal — agents · Evasão e Anti-Forense**
- [ ] Spoofing de nome de processo (manipulação de `argv[0]` no Linux)
- [ ] Manipulação de timestamp de arquivos (timestomping)
- [ ] Adulteração de logs — remoção seletiva de entradas `wtmp` / `auth.log`
- [ ] Execução somente em memória — sem artefato em disco
- [ ] Mimicry de tráfego C2 (disfarçar como HTTPS, DNS ou WebSocket)
- [ ] Ofuscação de sleep — encriptar memória do implant durante intervalos de sleep
- [ ] Unhooking de hooks EDR em `ntdll.dll` (Windows, cópia limpa do disco)
- [ ] Técnica Heaven's Gate (transição de chamada 32-bit → 64-bit)

---

**Arsenal — agents · Hardware**
- [ ] **Arduino / ATmega** — ataque USB HID (BadUSB): injeção de keystrokes para Linux e Windows
- [ ] Scripts compatíveis com Rubber Ducky (formato DuckyScript)
- [ ] **Raspberry Pi Zero W** — implant Wi-Fi headless com tunnel SSH reverso para C2
- [ ] **ESP8266 / ESP32** — deauth Wi-Fi beacon, evil twin AP e portal cativo
- [ ] **Flipper Zero** — scripts de payload: ataques replay SubGHz, clonagem NFC/RFID, IR, BadUSB
- [ ] Clonagem de cartão RFID 125kHz (EM4100 / HID Prox) com Proxmark3
- [ ] Crack MIFARE Classic 1K (autenticação nested + darkside attack)
- [ ] Gravação e replay de sinal RF com RTL-SDR / HackRF
- [ ] Acesso a console UART — dump de bootloader e shell root
- [ ] Exploração de interface JTAG / SWD (extração de firmware)

---

**Infraestrutura & DevOps**
- [ ] Docker Compose (API + MySQL + Redis em containers)
- [ ] Dockerfile para a API Spring Boot
- [ ] Build Tauri para produção (pacotes `.deb`, `.AppImage`, `.exe`, `.dmg`)
- [ ] GitHub Actions CI — build, teste, push de imagem Docker
- [ ] Templates Terraform para infraestrutura de lab (VMs, VPC, VPN)
- [ ] Playbook Ansible para deploy automatizado do servidor C2
- [ ] Guia de configuração de redirector (reverse proxy Apache / Nginx para tráfego C2)

---

## Aviso Legal

Este projeto foi desenvolvido **exclusivamente para fins educacionais, pesquisa de segurança ofensiva e exercícios em ambiente controlado** — laboratórios de pentest, operações Red Team com autorização prévia e escrita do proprietário da infraestrutura, e competições CTF.

**Utilizar esta ferramenta contra sistemas sem autorização prévia é crime**, potencialmente violando:
- **Brasil:** Lei nº 12.737/2012 (Lei Carolina Dieckmann) e Art. 154-A do Código Penal
- **EUA:** Computer Fraud and Abuse Act (CFAA)
- Legislação equivalente em outras jurisdições

O autor **não assume nenhuma responsabilidade** por qualquer uso indevido, aplicação ilegal ou dano causado pelo uso desta plataforma fora dos contextos autorizados descritos acima.

---

<div align="center">

<img src="https://capsule-render.vercel.app/api?type=waving&color=0d0d0d&height=120&section=footer" />

**Zombie Keeper** — *Construído para quem entende os dois lados da parede.*

[![GitHub](https://img.shields.io/badge/GitHub-jtave111-181717?style=flat-square&logo=github)](https://github.com/jtave111)

</div>
