# ZombieKeeper — Monorepo Structure

This project is a **monorepo** containing the full ZombieKeeper C2 platform: backend API, web dashboard, native agents, and automation scripts.

---

## Repository Layout

```
ZombieKeeper/
│
├── ZombieKeeper-Api/               # Spring Boot 4 · Java 21 · C2 REST API
│   ├── src/                        # Java source code
│   ├── .env                        # Environment variables (gitignored)
│   ├── pom.xml                     # Maven module POM
│   └── mvnw                        # Maven wrapper
│
├── ZombieKeeper-Web/               # Next.js 15 · React 19 · Operator dashboard
│   ├── src/                        # TypeScript/TSX source code
│   ├── .env.local                  # Frontend env variables (gitignored)
│   └── package.json
│
├── ZombieKeeper-Arsenal/                        # All native agents, exploits & automation
│   ├── cpp/                        # C++17 projects
│   │   ├── LocalFingerPrint/       # Network fingerprint agent (own project)
│   │   └── Ping/                   # ICMP raw socket library (own project)
│   ├── python/                     # Python projects
│   │   └── LocalFingerPrint/       # HTTP automation for C2 interaction
│   ├── go/                         # Go projects (planned)
│   ├── rust/                       # Rust projects (planned)
│   ├── assembly/                   # x86-64 shellcode & exploit dev (planned)
│   └── windows/                    # Windows agents & tooling (planned)
│
├── pom.xml                         # Maven aggregator (root, packaging=pom)
├── start.sh                        # Startup script for all services
├── README.md
├── MONOREPO.md                     # This file
└── HELP.md                         # Developer reference guide
```

---

## Running the Platform

### Quick start (all services)

```bash
./start.sh
```

### With API recompile

```bash
./start.sh --build
```

### Individual services

```bash
# API only
./start.sh --api-only

# Web dashboard only
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

## Building for Production

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

### C++ Agent

```bash
cd ZombieKeeper-Arsenal/cpp/LocalFingerPrint
make
sudo ./LocalFingerPrint
```

---

## Environment Variables

Both modules require their own environment files. **These files are gitignored — never commit credentials.**

| File | Module | Required |
|---|---|---|
| `ZombieKeeper-Api/.env` | API Server | Yes |
| `ZombieKeeper-Web/.env.local` | Web Dashboard | Yes |

See [HELP.md](HELP.md) for the full list of variables.

---

## Maven Aggregator

The root `pom.xml` is a **pure aggregator** (`<packaging>pom</packaging>`). It allows running Maven commands from the root that apply to all Java modules.

```bash
# Build all Java modules from root
./mvnw clean package -DskipTests -f pom.xml
```

`ZombieKeeper-Api` keeps `spring-boot-starter-parent` as its own parent — the root POM does not interfere with Spring Boot's dependency management.

---

## Module Status

| Module | Path | Status |
|---|---|---|
| ZombieKeeper-Api | `ZombieKeeper-Api/` | Stable · port 8080 |
| ZombieKeeper-Web | `ZombieKeeper-Web/` | Stable · port 3000 |
| C++ LocalFingerPrint | `ZombieKeeper-Arsenal/cpp/LocalFingerPrint/` | Stable |
| C++ Ping | `ZombieKeeper-Arsenal/cpp/Ping/` | Stable (lib) |
| Python LocalFingerPrint | `ZombieKeeper-Arsenal/python/LocalFingerPrint/` | Partial |
| Go modules | `ZombieKeeper-Arsenal/go/` | Planned |
| Rust modules | `ZombieKeeper-Arsenal/rust/` | Planned |
| Assembly / Exploits | `ZombieKeeper-Arsenal/assembly/` | Planned |
| Windows agent | `ZombieKeeper-Arsenal/windows/` | Planned |
