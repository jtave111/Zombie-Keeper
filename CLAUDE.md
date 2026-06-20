# ZombieKeeper — Contexto do Projeto

> APENAS PARA USO AUTORIZADO — Laboratórios de pentest, operações Red Team com
> autorização escrita, competições CTF e pesquisa de segurança ofensiva.

---

## O que é este projeto

ZombieKeeper é um framework C2 (Command & Control) para operações ofensivas
autorizadas. O operador usa um cliente desktop (Tauri), gerencia agentes implantados
em máquinas alvo, executa comandos remotos, coleta loot e mapeia redes locais.

---

## Estrutura do monorepo

```
ZombieKeeper/
├── ZombieKeeper-Api/        Spring Boot 4 — teamserver REST + WebSocket
├── ZombieKeeper-Client/     Tauri 2 + Vite + React 19 — cliente desktop do operador
├── ZombieKeeper-Arsenal/    C++17 — ferramentas de rede (scanner, DoS)
└── ZombieKeeper-Automations/ Python — scripts de automação / recon
```

---

## ZombieKeeper-Api

**Stack:** Spring Boot 4.0.0 · Java 21 · Hibernate 7 · MySQL 8 · JJWT 0.12.5

### Estrutura de pacotes

```
com.manager.Zombie_Keeper/
├── configuration/
│   ├── security/        CorsConfig, JwtAuthFilter, SecurityConfig, JwtHandshakeInterceptor
│   └── webSockets/      WebSocketsConfig
├── controller/
│   ├── agent/           AgentRestController
│   ├── auth/            AuthRestController
│   ├── c2_server/       InfoServerController, TerminalController
│   └── localNetwork/    ReconRestController
├── dtos/                agentDto, authDto, localNetworkDto (records/classes de request/response)
├── exception/           DuplicateAgentException
├── handler/webSockets/  TerminalWebSocketsHandler
├── model/
│   ├── entity/
│   │   ├── agent/       Agent, AgentLocation, Loot
│   │   ├── auth/        User, Role
│   │   ├── c2Server/    C2Server, ApiConfig, AutomationConfig, DatabaseConfig,
│   │   │                NetworkConfig, PortConfig, SecurityConfig, ServerLocation, WebConfig
│   │   └── localNetwork/ NetworkNode, NetworkSession, Port, Vulnerability
│   └── enums/
│       ├── agent/       StatusAgent (ONLINE/OFF/KILL), Flags, Tags, LocationSource
│       ├── server/      StatusServer (ONLINE/OFFLINE)
│       └── vulns/       SeverityLevel
├── repository/
│   ├── agent/           AgentRepository, AgentLocationRepository, LootRepository
│   ├── auth/            UserRepository, RoleRepository
│   ├── c2server/        C2ServerRepository, ApiConfigRepository, AutomationConfigRepository,
│   │                    DatabaseConfigRepository, NetworkConfigRepository, PortConfigRepository,
│   │                    SecurityConfigRepository, ServerLocationRepository, WebConfigRepository
│   └── localNetwork/    NetworkNodeRepository, NetworkSessionRepository, PortRepository, VulnerabilityRepository
├── service/
│   ├── agents/          AgentsService, AgentLocationService
│   ├── auth/            AuthService, CustomUserDetailsService
│   ├── c2_server/       C2ServerInfoService
│   ├── localNetwork/    LocalNetworkDatabaseManagerService, LocalNetworkFingerprintService
│   ├── processManagerService/ ProcessManagerService
│   └── properties/      PropertiesServices
└── util/                JwtUtil
```

### Hierarquia de entidades C2Server

```
C2Server (tb_c2_server)
├── NetworkConfig[]  (tb_network_config) — interfaces de rede
│   └── PortConfig[] (tb_port_config)   — portas por interface
│       ├── ApiConfig  (tb_api_config)  — config da REST API
│       ├── WebConfig  (tb_web_config)  — config do dashboard
│       └── DatabaseConfig (tb_db_config)
├── DatabaseConfig[] — configs de BD diretamente no server
├── AutomationConfig[] (tb_automation_config)
├── SecurityConfig   (tb_security_config)  — JWT, bcrypt, lockout
├── ServerLocation[] (tb_server_location)  — geolocalização do C2
└── WebConfig        — config do dashboard (OneToOne direto)
```

### Variáveis de ambiente

Carregadas do arquivo `ZombieKeeper-Api/.env` via `loadDotEnv()` no `main()`
antes do Spring inicializar (spring-dotenv 4.0.0 não é compatível com Spring Boot 4).

Principais: `DB_HOST`, `DB_PORT`, `DB_NAME`, `DB_USERNAME`, `DB_PASSWORD`,
`JWT_SECRET`, `JWT_EXPIRATION`, `SERVER_PORT`, `CORS_ALLOWED_ORIGINS`.

### WebSocket terminal

Endpoint: `ws://host/term?token=JWT` — handler: `TerminalWebSocketsHandler`.
O token vai na query string porque o protocolo WebSocket não suporta headers customizados no upgrade.

---

## ZombieKeeper-Client

**Stack:** Tauri 2 · Vite 5 · React 19 · TypeScript · Tailwind CSS

**Branch de desenvolvimento:** `feat/tauri-desktop`

### Arquitetura

App desktop nativo (Linux/Windows/macOS). Sem proxy, sem servidor Node.js.
O cliente Tauri fala diretamente com o Spring Boot:

```
App Desktop (Tauri) → Spring Boot :8080
```

Token JWT armazenado em **localStorage**. Auth gerenciado por `Root.tsx` via evento `zk:logout`.

### Estrutura

```
ZombieKeeper-Client/
├── src-tauri/               ← core Rust (Tauri 2)
│   ├── Cargo.toml
│   ├── build.rs
│   ├── tauri.conf.json      ← janela: 1440x900, identifier: com.zombiekeeper.c2
│   └── src/
│       ├── main.rs
│       └── lib.rs
├── src/
│   ├── main.tsx             ← entrypoint Vite → monta <Root />
│   ├── Root.tsx             ← gerencia auth: mostra LoginPage ou App
│   ├── components/
│   │   ├── layout/          App.tsx (roteamento de views), LoginPage.tsx, Sidebar, Menubar
│   │   ├── agents/          AgentsView, AgentTableHeader, AgentShell
│   │   ├── dashboard/       DashboardView (React.lazy), WorldMap (Leaflet)
│   │   ├── shell/           ShellModule (C2 shell interativo + WebSocket)
│   │   ├── users/           UsersView (CRUD de operadores)
│   │   ├── network/         NetworkView
│   │   ├── intelligence/    LootView, CredentialsView, ReportsView
│   │   ├── listeners/       ListenersView
│   │   ├── payloads/        PayloadGenerator
│   │   └── shared/          SettingsView
│   ├── lib/
│   │   ├── client/
│   │   │   └── api.ts       ← único ponto de API: chama Spring Boot diretamente
│   │   │                       Exporta: auth, agentsApi, c2Api, usersApi,
│   │   │                       toAgent, toAgentGeo, mapStatus, shellWsUrl()
│   │   ├── dtos/            ← espelham exatamente o que o Spring Boot retorna
│   │   │   ├── agent/agentDto.ts
│   │   │   ├── c2Server/c2ServerDto.ts
│   │   │   ├── localNetwork/localNetworkDto.ts
│   │   │   └── user/user.ts
│   │   └── models/          ← estruturas internas (legado — preferir dtos/)
│   └── styles/globals.css
├── index.html
├── vite.config.ts
├── package.json
└── BACKEND_CHANGES.md       ← ajustes necessários no Spring Boot (CORS, login response)
```

### Endpoints Spring Boot chamados diretamente

| Método | Endpoint | Descrição |
|--------|----------|-----------|
| POST | `/api/auth/login` | login — retorna `{ token, username, status }` |
| GET | `/api/c2-server/agents` | listar agentes |
| GET/PUT | `/api/c2-server/agents/:id` | agente específico |
| GET | `/api/c2-server/info` | info do C2 |
| GET | `/api/auth/users` | listar operadores |
| GET | `/api/auth/roles` | listar roles |
| POST | `/api/auth/register` | criar operador |
| DELETE/PUT | `/api/auth/users/:id` | gerenciar operador |
| WS | `ws://host/term?token=JWT` | C2 shell |
| WS | `ws://host/term/:id?token=JWT` | shell de agente |

### Variáveis de ambiente

```
VITE_API_URL=http://localhost:8080
VITE_WS_URL=ws://localhost:8080
```

### Build / Dev

```bash
npm install
npm run tauri dev      # dev com hot-reload
npm run tauri build    # empacota: .AppImage (Linux), .exe/.msi (Windows), .dmg (macOS)
```

Requer Rust instalado: `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`

---

## ZombieKeeper-Arsenal (C++17)

Ferramentas compiladas via CMake/Makefile. Build: `make network-session` a partir de `ZombieKeeper-Arsenal/`.

```
ZombieKeeper-Arsenal/
├── libs/
│   └── cpp/
│       ├── net_utils/       ← utilitários compartilhados (net_utils::icmp_checksum)
│       ├── ping/            ← ICMP raw socket — linka net_utils
│       └── D_DOS/           ← TCP flood + ICMP ping flood — linka net_utils
└── network-session/
    └── tools/
        └── local-fingerprint/ ← scanner de rede local (fingerprint de hosts)
            ├── include/     ← headers da ferramenta
            ├── src/         ← implementações
            └── CMakeLists.txt
```

Convenção: `include/` para headers públicos, `src/` para implementação. Todas as libs seguem este padrão.

---

## ZombieKeeper-Automations (Python)

Scripts de automação para recon e integração com o C2. Configurados via `AutomationConfig`
no backend (pythonPath, scriptsDir, apiUrl, pollingIntervalMs).

---

## Convenções importantes

- **Typo histórico:** `OLINE` foi corrigido para `ONLINE` em todos os lugares
  (StatusAgent, StatusServer, agentDto.ts). Se aparecer `OLINE` em algum lugar novo, é bug.
- **`DatabaseConfig.schema`** mapeado como `@Column(name = "db_schema")` — `schema` é palavra reservada no MySQL.
- **spring-dotenv 4.0.0** não é compatível com Spring Boot 4 — o `.env` é carregado manualmente em `C2ServerApplication.main()` via `System.setProperty`.
- **JWT no client:** armazenado em `localStorage` (chave `zk_token`). Logout via `window.dispatchEvent(new Event('zk:logout'))` — `Root.tsx` escuta e desmonta o app.
- **WebSocket shell:** conecta diretamente ao Spring Boot via `shellWsUrl()` de `lib/client/api.ts`. Token vai na query string (`?token=JWT`) pois WS não suporta headers no upgrade.
- **CORS no backend:** deve liberar `http://localhost:1420` (dev Vite) e `tauri://localhost` / `https://tauri.localhost` (produção Tauri). Ver `BACKEND_CHANGES.md` no Client.
- **Arsenal `net_utils`:** checksum ICMP centralizado em `libs/cpp/net_utils/`. `ping` e `D_DOS` linkam `PRIVATE net_utils`. Novo scanner também deve adicionar `net_utils` antes de `ping` no seu CMakeLists.

---

## Estado atual do projeto

- Backend compilando e conectando ao MySQL
- Entidades JPA criadas para todos os domínios
- Repositories criados para todos os domínios
- Client migrado de Next.js para Tauri desktop (branch `feat/tauri-desktop`)
- WebSocket do shell conecta diretamente ao Spring Boot via `shellWsUrl()`
- CORS do backend ainda precisa ser atualizado para origens Tauri (ver `BACKEND_CHANGES.md`)
- Controllers e services ainda em desenvolvimento para vários endpoints
- Arsenal: `net_utils` criada, `ping` e `D_DOS` padronizadas com `include/` + `src/`

---

## Material de estudo — fora do monorepo

### Learning/ (ignorado pelo git — pessoal)

`/home/zero/dev/ZombieKeeper/Learning/low-level/` — conteúdo de aprendizado estruturado em fases:

| Fase | Tópico | Arquivos |
|------|--------|---------|
| 1 | Arquitetura x86-64 | registradores, instruções, stack frames, lendo assembly |
| 2 | Gerenciamento de Memória | virtual memory, heap internals (glibc chunks/tcache) |
| 3 | Syscalls do Linux | tabela, NASM puro, strace |
| 4 | Formato ELF | sections/segments, GOT/PLT lazy binding, RELRO |
| 5 | Redes em Baixo Nível | socket API, raw sockets, epoll |
| 6 | Exploits | buffer overflow completo, ROP (ret2win/libc/syscall/leak) |
| 7 | Kernel | LKMs do zero, eBPF + bpftrace + XDP |
| 8 | Instrumentação | debugger com ptrace do zero, disassembler + encoding x86-64 |

Ver índice completo: `Learning/low-level/INDICE-GERAL.md`

### Ideas/ (ignorado pelo git — pessoal)

`/home/zero/dev/ZombieKeeper/Ideas/` — ideias organizadas por área:

- `backend/` — event feed WebSocket, loot API, audit log
- `arsenal/` — agente implant (beacon), reverse shell C/NASM
- `seguranca-infra/` — mTLS, docker-compose completo
- `automations/` — auto-recon ao novo agente
- `low-level-aplicado/` — shellcode, ROP, heap exploitation, process injection,
  ELF packer (memfd_create), custom allocator, mini-debugger, mini-disassembler,
  kernel module, eBPF, side-channels (Flush+Reload/Spectre), JIT compiler, bootloader x86, anti-debug

Ver índice: `Ideas/low-level-aplicado/INDICE-COMPLETO.md`

---

## Módulos de exercícios — fora do monorepo

### /home/zero/dev/asm/

Módulo de exercícios x86-64 NASM (sem README/Makefile na raiz — padrão igual aos outros módulos):

```
asm/
└── exercises/
    ├── EXERCISES.md          ← ABI table + descrição dos exercícios
    ├── 01-hello-syscall/     ← write + exit (skeleton com TODOs)
    └── 02-echo/              ← read + write (skeleton com TODOs)
```

### /home/zero/dev/c/exercises/

Exercícios C com raw syscalls:

```
c/exercises/
├── EXERCISES.md              ← ensina syscall(), tabela, o que implementar
└── syscall-cat/              ← minimal cat sem libc (include/ + src/ + Makefile)
```

`syscall-cat` — 5 wrappers (`zk_open/read/write/close/exit`) + `main()`, tudo `/* TODO */`.

### Ferramentas instaladas para baixo nível

```
nasm, gdb + pwndbg, ghidra, radare2, cutter, IDA Free,
strace, valgrind (a instalar), ltrace (a instalar),
capstone, unicorn, pwntools, CLion, VS Code, Neovim
```

`nasm` ainda precisa ser instalado: `sudo pacman -S nasm`
