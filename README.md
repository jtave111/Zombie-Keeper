<div align="center">

 <img src="https://capsule-render.vercel.app/api?type=waving&color=333333&height=220&section=header&text=Zombie%20Keeper&fontSize=80&fontColor=ff0000&animation=fadeIn&fontAlign=50" alt="Zombie Keeper Header" />

  # Zombie Keeper – Command & Control System
   
  **Dual-Purpose Command & Control: Infrastructure Monitoring & Offensive Operations**
  
[![Java](https://img.shields.io/badge/Server-Java%2017%20%2B%20Spring%20Boot-6DB33F?style=for-the-badge&logo=spring&logoColor=white)](https://spring.io/)
[![JavaFX](https://img.shields.io/badge/UI-JavaFX%20%2B%20FXML-ED8B00?style=for-the-badge&logo=java&logoColor=white)](#)
[![C++](https://img.shields.io/badge/Agent-C%2B%2B17%20%2B%20Raw%20Sockets-00599C?style=for-the-badge&logo=cplusplus&logoColor=white)](https://isocpp.org/)
[![Python](https://img.shields.io/badge/Automation-Python%203-3776AB?style=for-the-badge&logo=python&logoColor=white)](#)
[![Maven](https://img.shields.io/badge/Build-Apache%20Maven-C71A36?style=for-the-badge&logo=apachemaven&logoColor=white)](#)
[![Spring Security](https://img.shields.io/badge/Auth-Spring%20Security%20%2B%20JWT-4CA154?style=for-the-badge&logo=springsecurity&logoColor=white)](#)

<br/>

> ⚠️ **USO EXCLUSIVO EM AMBIENTES CONTROLADOS** — Pentest labs, Red Team com autorização escrita, CTFs e pesquisa em segurança ofensiva. O uso não autorizado desta ferramenta é crime. Leia o [Aviso Legal](#-aviso-legal).

</div>

---

## 📌 Índice

- [Visão Geral](#-visão-geral)
- [Arquitetura Real do Sistema](#-arquitetura-real-do-sistema)
- [Módulos do Projeto](#-módulos-do-projeto)
  - [Server — Spring Boot C2 (Java)](#1-server--spring-boot-c2-java)
  - [Agent — Network Scanner (C++)](#2-agent--network-scanner-c)
  - [Automation — Python Scripts](#3-automation--python-scripts)
- [Stack Tecnológica](#-stack-tecnológica)
- [Estrutura do Projeto](#-estrutura-do-projeto)
- [Instalação e Setup](#-instalação-e-setup)
- [Uso](#-uso)
- [Roadmap](#-roadmap)
- [Aviso Legal](#-aviso-legal)

---

## 🧬 Visão Geral

O **Zombie Keeper** é uma plataforma de **Command & Control (C2)** de uso dual — ofensivo e defensivo — desenvolvida do zero com foco em aprendizado de segurança ofensiva e operações controladas de Red/Blue Team.

O sistema é composto por três camadas que operam em conjunto:

- **C2 Server** → Aplicação Spring Boot com interface JavaFX desktop, responsável por orquestrar agentes, receber telemetria de rede, gerenciar sessões e autenticar operadores.
- **Network Agent** → Binário C++ compilado com Raw Sockets que realiza fingerprint local, mapeamento de topologia via ICMP/ARP e enumeração de portas na sub-rede do host comprometido.
- **Automation Layer** → Scripts Python para automação de requisições e integração com o servidor C2.

---

## 🏗️ Arquitetura Real do Sistema

```
┌─────────────────────────────────────────────────────────────────────┐
│                      ZOMBIE KEEPER C2 SERVER                        │
│                     (Spring Boot 3 + JavaFX)                        │
│                                                                     │
│  ┌──────────────────┐    ┌──────────────────┐    ┌───────────────┐  │
│  │  JavaFX UI Layer │    │   REST API Layer  │    │  Auth Layer   │  │
│  │                  │    │                  │    │               │  │
│  │  main_dashboard  │    │  AgentRestCtrl   │    │  Spring       │  │
│  │  agents.fxml     │    │  ReconRestCtrl   │    │  Security +   │  │
│  │  scanner.fxml    │    │  AuthRestCtrl    │    │  JWT / Roles  │  │
│  │  network_session │    │  UserRestCtrl    │    │               │  │
│  │  settings.fxml   │    └────────┬─────────┘    └───────────────┘  │
│  └──────────────────┘             │                                  │
│                                   │ JPA / Hibernate                  │
│                          ┌────────▼─────────┐                        │
│                          │   Service Layer  │                        │
│                          │                  │                        │
│                          │  AgentsService   │                        │
│                          │  AuthService     │                        │
│                          │  FingerprintSvc  │                        │
│                          │  ProcessMgrSvc   │                        │
│                          │  NetworkDB Mgr   │                        │
│                          └────────┬─────────┘                        │
│                                   │                                  │
│                     ┌─────────────▼──────────────────────────────┐   │
│                     │           Data Model (JPA Entities)         │   │
│                     │  Agent · Loot · NetworkNode · NetworkSession │   │
│                     │  Port · Vulnerability · User · Role         │   │
│                     └─────────────────────────────────────────────┘  │
└────────────────────────────────┬────────────────────────────────────┘
                                 │ HTTP (register.cpp) / Raw Socket C2
                    ┌────────────▼────────────┐
                    │    C++ ZOMBIE AGENT      │
                    │  (Linux / Windows)       │
                    │                          │
                    │  FingerPrintSession      │
                    │  Scanner (Raw Sockets)   │
                    │  Node · Port · Session   │
                    │  Vulnerability Model     │
                    │  Ping (ICMP Sweep)       │
                    └──────────────────────────┘
```

---

## 📦 Módulos do Projeto

### 1. Server — Spring Boot C2 (Java)

O servidor é o núcleo de controle da plataforma. Construído com **Spring Boot 3**, expõe tanto uma interface desktop via **JavaFX + FXML** quanto uma **REST API** para integração com agentes e scripts externos.

#### Camada de API REST (`src/main/java/.../api/controller/`)

| Controller | Responsabilidade |
|---|---|
| `AgentRestController` | Registro, listagem e gestão de agentes ativos |
| `ReconRestController` | Recebimento de dados de fingerprint enviados pelo agente C++ |
| `AuthRestController` | Login e geração de tokens JWT |
| `UserRestController` | Gestão de operadores da plataforma |

#### Interface Desktop JavaFX (`src/main/java/.../ui/`)

A navegação entre telas é gerenciada pelo `SceneManager` usando o `ViewEnum` como mapa de rotas. Cada tela FXML tem seu próprio controller dedicado:

| Tela FXML | Controller | Função |
|---|---|---|
| `main_dashboard.fxml` | `DashboardUiController` | Painel central de operações |
| `agents.fxml` | `AgentUIController` + `LootUIController` | Visualização de Zombies e dados coletados |
| `ScannerManager.fxml` / `scanner.fxml` | `ScannerManagerController` | Disparo e gestão de sessões de scan |
| `network_session.fxml` | `NetworkSessionUIController` + `NetworkNodeUIController` | Detalhamento de topologia descoberta |
| `login.fxml` | `AuthUiController` | Autenticação de operadores |
| `settings.fxml` | `SettingsUiController` | Configurações da plataforma |
| `home.fxml` | `HomeUiController` | Tela inicial pós-login |

#### Modelo de Dados (`src/main/java/.../model/`)

```
Agent          → representa um host comprometido (Zombie)
  └── Loot     → arquivos/credenciais extraídos do agente

NetworkSession → sessão completa de fingerprint de uma sub-rede
  └── NetworkNode     → host descoberto na varredura
        └── Port          → porta aberta identificada no host
              └── Vulnerability → fraqueza associada à porta/serviço

User  → operador da plataforma
  └── Role → permissão de acesso (ex: ADMIN, OPERATOR)

Enums:
  Flags         → estados/flags de comportamento de um agente
  Tags          → categorização de agentes por tipo/objetivo
  SeverityLevel → classificação de vulnerabilidades (LOW / MEDIUM / HIGH / CRITICAL)
```

#### Serviços (`src/main/java/.../service/`)

- **`AgentsService`** — Ciclo de vida dos agentes: registro, atualização de status, consulta de Loot
- **`AuthService`** — Autenticação de operadores com Spring Security e controle de roles
- **`LocalNetworkFingerprintService`** — Orquestra a execução do agente C++ e processa os resultados recebidos
- **`LocalNetworkDatabaseManagerService`** — Persiste os dados de rede (Nodes, Ports, Vulnerabilities) no banco de dados
- **`ProcessManagerService`** — Gerencia a execução de processos externos via `ProcessBuilder` (binário do agente C++)

#### Segurança (`src/main/java/.../configuration/security/`)

- **`SecurityConfig`** — Configuração central do Spring Security: filtros JWT, rotas protegidas e roles de acesso
- **`CorsConfig`** — Política de CORS para comunicação cross-origin com agentes e automações externas

---

### 2. Agent — Network Scanner (C++)

O agente é um binário nativo compilado em **C++17** usando **Raw Sockets** (POSIX no Linux). Ele pode ser invocado diretamente pelo servidor via `ProcessManagerService` ou deployado manualmente em um host-alvo.

#### Estrutura (`modules/linux/c++/code/localNetwork/`)

```
main.cpp                  → Entry point da aplicação
App.cpp / App.h           → Controlador principal do agente

FingerPrintSession.cpp    → Orquestra a sessão completa de fingerprint
SessionBuild.cpp          → Constrói e serializa o objeto Session para envio HTTP

model/
├── Node.cpp/h            → Host descoberto na sub-rede
├── Port.cpp/h            → Porta aberta e protocolo identificado
├── Session.cpp/h         → Sessão agregada (contém lista de Nodes)
└── Vulnerability.cpp/h  → Vulnerabilidade mapeada a uma porta

scanners/
└── Scanner.cpp/h        → Engine de varredura via Raw Sockets

../ping/
└── Ping.cpp/h            → ICMP sweep para host discovery
```

#### Fluxo de Execução

```
Início
  │
  ▼
App::run()
  │
  ▼
FingerPrintSession::start()
  │
  ├──► Ping::sweep()
  │         Envia pacotes ICMP para cada IP da sub-rede
  │         Mapeia hosts ativos
  │
  ├──► Scanner::portScan()
  │         Raw socket scan nas portas de cada host ativo
  │         Identifica serviços e protocolos
  │
  ├──► Model::build()
  │         Constrói Node → Port → Vulnerability para cada resultado
  │
  └──► SessionBuild::serialize()
            Serializa a Session completa
            Envia ao C2 Server via HTTP POST
```

#### Scripts de Deploy (`src/main/resources/static/auxScripts/`)

| Arquivo | Função |
|---|---|
| `windows/c++/HTTP/register.cpp` | Código C++ executado no host Windows para registrar o agente no C2 via HTTP |
| `linux/` | Diretório para scripts de deploy Linux (em desenvolvimento) |
| `windows/python/` | Automação de deploy via Python no Windows (em desenvolvimento) |

---

### 3. Automation — Python Scripts

Scripts para automação de fluxos de integração com o servidor C2.

```
modules/python/localFingerPrint/
├── automation/           → Automação geral (em desenvolvimento)
└── requestAutomation/
    └── request.py        → Automação de requisições HTTP ao C2 Server
```

---

## 🛠️ Stack Tecnológica

| Componente | Tecnologia |
|---|---|
| C2 Server | Java 17 + Spring Boot 3.x |
| Interface Desktop | JavaFX + FXML |
| ORM / Persistência | Spring Data JPA + Hibernate |
| Banco de Dados | H2 (dev) / PostgreSQL (prod) |
| Autenticação | Spring Security + JWT + Roles |
| API REST | Spring Web MVC + Jackson |
| Monitoramento | Spring Actuator + Micrometer |
| Network Agent | C++17 + Raw Sockets (POSIX / WinSock2) |
| Build Server | Apache Maven (mvnw wrapper incluso) |
| Build Agent | GNU Make |
| Automação | Python 3 |

---

## 📁 Estrutura do Projeto

```
Zombie-Keeper/
│
├── src/                                      # C2 Server (Spring Boot + JavaFX)
│   └── main/
│       ├── java/com/manager/Zombie_Keeper/
│       │   ├── api/controller/               # REST: Agent, Auth, User, Recon
│       │   ├── ui/controller/                # JavaFX: Dashboard, Agents, Scanner...
│       │   ├── ui/manager/                   # SceneManager + ViewEnum
│       │   ├── service/                      # Agents, Auth, Fingerprint, ProcessMgr
│       │   ├── model/entity/                 # JPA: Agent, Loot, NetworkNode, Port...
│       │   ├── model/enums/                  # Flags, Tags, SeverityLevel
│       │   ├── repository/                   # Spring Data Repositories
│       │   ├── configuration/security/       # SecurityConfig + CorsConfig
│       │   ├── dtos/                         # DTOs de request/response
│       │   └── exception/                    # DuplicateAgentException
│       └── resources/
│           ├── fxml/                         # Telas JavaFX
│           ├── static/css/                   # Estilos das telas
│           ├── static/imgs/                  # Assets visuais
│           └── static/auxScripts/            # Scripts de deploy de agentes
│
├── modules/                                  # Módulos nativos e automação
│   ├── linux/c++/code/
│   │   ├── localNetwork/                     # Agente C++: Scanner, FingerPrint, Models
│   │   └── ping/                             # ICMP Ping via Raw Sockets
│   ├── python/localFingerPrint/              # Automação Python
│   └── windows/                              # Agente Windows (em desenvolvimento)
│
├── pom.xml                                   # Maven build config
└── mvnw / mvnw.cmd                           # Maven wrapper
```

---

## 🚀 Instalação e Setup

### Pré-requisitos

- **Java 17+** e **Maven 3.8+** (servidor)
- **GCC 11+** com suporte a C++17 no Linux — ou **MSVC 2022** no Windows (agente)
- **Python 3.10+** (scripts de automação)
- Permissões **root/administrador** no host onde o agente será executado (Raw Sockets exigem privilégios elevados)

### 1. Clonar o repositório

```bash
git clone https://github.com/jtave111/Zombie-Keeper.git
cd Zombie-Keeper
```

### 2. Iniciar o C2 Server

```bash
./mvnw spring-boot:run
```

A interface JavaFX abrirá automaticamente. O servidor REST fica disponível em `http://localhost:8080`.

### 3. Compilar o Agente C++ (Linux)

```bash
cd modules/linux/c++/code/localFingerPrint
make
```

O binário `LocalFingerPrint` será gerado no mesmo diretório.

### 4. Executar o Agente

```bash
# Raw Sockets requerem privilégios elevados
sudo ./LocalFingerPrint
```

O agente realizará o fingerprint da sub-rede local e enviará os resultados ao C2 Server via HTTP.

---

## 💻 Uso

### Fluxo de Operação

**1. Login** — Autentique-se na tela `login.fxml` com suas credenciais de operador.

**2. Dashboard** — O `main_dashboard` exibe o panorama geral: agentes ativos, sessões de rede recentes e alertas.

**3. Agentes (`agents.fxml`)** — Visualize todos os Zombies registrados com status, flags e tags. Acesse os Loots coletados de cada agente.

**4. Scanner (`ScannerManager.fxml`)** — Inicie uma sessão de fingerprint em um agente ativo. O `ProcessManagerService` invoca o binário C++, que executa no host-alvo e retorna a topologia da sub-rede.

**5. Sessão de Rede (`network_session.fxml`)** — Explore os resultados: hosts descobertos (`NetworkNode`), portas abertas (`Port`) e vulnerabilidades mapeadas (`Vulnerability`) com nível de severidade.

**6. Settings (`settings.fxml`)** — Configure parâmetros do servidor e preferências da plataforma.

---

## 🗺️ Roadmap

**Servidor C2**
- [x] Arquitetura Spring Boot + REST API + JavaFX UI
- [x] Autenticação com Spring Security + Roles (ADMIN / OPERATOR)
- [x] Modelo de dados completo: Agent, Loot, NetworkSession, NetworkNode, Port, Vulnerability
- [x] `ProcessManagerService` para execução de binários externos
- [x] Configuração de CORS e Spring Security
- [ ] Canal C2 persistente via WebSocket (comunicação bidirecional em tempo real)
- [ ] Mapa visual de topologia de rede no dashboard
- [ ] Módulo de Loot: upload e visualização de arquivos exfiltrados
- [ ] Exportação de relatórios de sessão (PDF/JSON)
- [ ] Integração com MITRE ATT&CK Navigator

**Agente C++**
- [x] ICMP sweep para host discovery (`Ping.cpp`)
- [x] Port scanner via Raw Sockets (`Scanner.cpp`)
- [x] Modelo de dados: Session, Node, Port, Vulnerability
- [x] Serialização e envio HTTP dos resultados ao C2
- [x] Suporte Linux com build via Make
- [ ] Suporte Windows completo (estrutura `modules/windows/` criada)
- [ ] Canal C2 persistente (keep-alive com o servidor)
- [ ] Banner grabbing para identificação de versões de serviços
- [ ] Correlação automática com CVEs conhecidos
- [ ] Módulos de post-exploitation

**Automação Python**
- [x] Script base de requisições HTTP (`request.py`)
- [ ] Automação de fluxo completo de registro de agente
- [ ] Parser de sessões de rede para análise offline

---
## 📜 Aviso Legal

Este projeto foi desenvolvido **exclusivamente para fins educacionais, pesquisa em segurança ofensiva e exercícios em ambientes controlados** — laboratórios de pentest, operações de Red Team com autorização escrita e explícita do proprietário da infraestrutura, e competições de CTF.

**O uso desta ferramenta contra sistemas sem autorização prévia é crime**, podendo violar:
- **Brasil:** Lei nº 12.737/2012 (Lei Carolina Dieckmann) e art. 154-A do Código Penal
- **EUA:** Computer Fraud and Abuse Act (CFAA)
- Legislações equivalentes em outras jurisdições

O autor **não se responsabiliza** por qualquer uso indevido, ilegal ou dano causado pelo uso desta plataforma fora dos contextos autorizados descritos acima.

---

<div align="center">

<img src="https://capsule-render.vercel.app/api?type=waving&color=0d0d0d&height=120&section=footer" />

**Zombie Keeper** — *Built for those who understand both sides of the wall.*

[![GitHub](https://img.shields.io/badge/GitHub-jtave111-181717?style=flat-square&logo=github)](https://github.com/jtave111)

</div>