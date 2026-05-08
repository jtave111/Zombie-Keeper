# ZombieKeeper — Developer Reference

Quick reference for setting up, configuring, and working with the ZombieKeeper platform.

---

## Prerequisites

| Tool | Version | Install |
|---|---|---|
| Java JDK | 21+ | [adoptium.net](https://adoptium.net/) |
| Maven | 3.8+ | Bundled via `mvnw` wrapper |
| Node.js | 20+ | [nodejs.org](https://nodejs.org/) |
| MySQL | 8+ | `apt install mysql-server` |
| GCC/G++ | 11+ (C++17) | `apt install build-essential` |
| Python | 3.10+ | `apt install python3` |

---

## Environment Setup

### API Server (`ZombieKeeper-Api/.env`)

Create this file before running the API. It is gitignored — never commit it.

```env
# Database
DB_HOST=localhost
DB_PORT=3306
DB_NAME=c2_db
DB_USERNAME=root
DB_PASSWORD=your_password
DB_URL=jdbc:mysql://${DB_HOST}:${DB_PORT}/${DB_NAME}?createDatabaseIfNotExist=true&useSSL=false&allowPublicKeyRetrieval=true&serverTimezone=UTC

# JWT
JWT_SECRET=your-secret-at-least-32-chars-long
JWT_EXPIRATION=86400000
JWT_REFRESH_EXPIRATION=604800000

# Server
SERVER_PORT=8080
SERVER_ADDRESS=0.0.0.0

# CORS (must include the web dashboard origin)
CORS_ALLOWED_ORIGINS=http://localhost:3000,http://localhost:8080
CORS_ALLOWED_METHODS=GET,POST,PUT,DELETE,PATCH,OPTIONS
CORS_ALLOWED_HEADERS=*
CORS_ALLOW_CREDENTIALS=true

# Liquibase
LIQUIBASE_ENABLED=true
LIQUIBASE_DROP_FIRST=false

# Default admin account (created on first run)
ADMIN_USERNAME=admin
ADMIN_PASSWORD=ChangeMe!2024
ADMIN_EMAIL=admin@zombiekeeper.local

# Spring profile
SPRING_PROFILES_ACTIVE=dev

# File upload (Loot)
FILE_UPLOAD_DIR=./uploads
FILE_MAX_SIZE=10485760

# C2 config
C2_AGENT_TIMEOUT=300000
C2_HEARTBEAT_INTERVAL=60000
C2_MAX_AGENTS=1000

# Optional: external API keys
NVD_API_KEY=
SHODAN_API_KEY=
VIRUSTOTAL_API_KEY=
```

### Web Dashboard (`ZombieKeeper-Web/.env.local`)

```env
NEXT_PUBLIC_API_URL=http://localhost:8080
```

---

## API Endpoints

Base URL: `http://localhost:8080`

Authentication: `Authorization: Bearer <jwt_token>`

### Auth

| Method | Path | Auth | Description |
|---|---|---|---|
| `POST` | `/api/auth/login` | No | Login and get JWT token |
| `GET` | `/api/auth/users` | Admin | List all operators |
| `POST` | `/api/auth/register` | Admin | Create new operator |
| `PUT` | `/api/auth/users/{id}/role` | Admin | Update operator role |
| `PUT` | `/api/auth/users/{id}/password` | Admin | Change operator password |
| `DELETE` | `/api/auth/users/{id}` | Admin | Remove operator |
| `GET` | `/api/auth/roles` | Admin | List available roles |

**Login example:**
```bash
curl -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"ChangeMe!2024"}'
```

### Agents

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/c2-server/agents` | List all registered agents |
| `GET` | `/api/c2-server/agents/{id}` | Get agent by ID |
| `PUT` | `/api/c2-server/agents/{id}/ping` | Update agent heartbeat |
| `PUT` | `/api/c2-server/agents/{id}/delete` | Soft-delete agent |
| `GET` | `/api/c2-server/info` | C2 server info and stats |

### Recon

| Method | Path | Description |
|---|---|---|
| `POST` | `/api/recon/local` | Receive network scan results from C++ agent |

---

## Database Setup

The API uses **MySQL 8** with **Liquibase** for schema migrations. The database is created automatically if it does not exist (requires `createDatabaseIfNotExist=true` in the JDBC URL).

```sql
-- Create the database manually if needed
CREATE DATABASE c2_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
```

Liquibase runs migrations on startup. To reset the schema (dev only):

```env
LIQUIBASE_DROP_FIRST=true
```

> Set back to `false` after reset to avoid wiping data on the next restart.

---

## Common Development Tasks

### Run API in development mode

```bash
cd ZombieKeeper-Api
./mvnw spring-boot:run
```

### Run Web in development mode

```bash
cd ZombieKeeper-Web
npm run dev
```

### Run full type check (Web)

```bash
cd ZombieKeeper-Web
npx tsc --noEmit
```

### Build production JAR

```bash
cd ZombieKeeper-Api
./mvnw clean package -DskipTests
```

### Build production Web

```bash
cd ZombieKeeper-Web
npm run build
npm start
```

### Compile C++ agent

```bash
cd ZombieKeeper-Arsenal/cpp/LocalFingerPrint
make

# Clean build
make clean && make
```

### Run C++ agent

```bash
# Requires root (Raw Sockets need CAP_NET_RAW)
sudo ./LocalFingerPrint
```

---

## Project Notes

- **Package name:** The Spring Boot application uses `com.manager.Zombie_Keeper` (underscore) because `com.manager.Zombie-Keeper` is not a valid Java package name.
- **Token storage:** The web dashboard stores the JWT in `localStorage` under the key `zk_token`.
- **Agent polling:** The dashboard polls `/api/c2-server/agents` every 30 seconds via `setInterval`.
- **Map SSR:** The Leaflet world map (`WorldMap.tsx`) uses `next/dynamic` with `ssr: false` because Leaflet requires the browser DOM.
- **CORS:** The API's `CorsConfig` must include the web dashboard origin. Update `CORS_ALLOWED_ORIGINS` if deploying on a different host/port.
- **Liquibase:** Schema migrations live in `src/main/resources/db/changelog/`. Do not edit the database schema manually — always add a new changeset.

---

## Troubleshooting

**API won't start — "DB connection refused"**
- Ensure MySQL is running: `sudo systemctl start mysql`
- Check `DB_HOST`, `DB_PORT`, `DB_USERNAME`, `DB_PASSWORD` in `.env`

**Web shows "Network Error" / "Failed to fetch"**
- Confirm the API is running on `http://localhost:8080`
- Check `NEXT_PUBLIC_API_URL` in `ZombieKeeper-Web/.env.local`
- Check `CORS_ALLOWED_ORIGINS` includes `http://localhost:3000`

**C++ agent fails with "Operation not permitted"**
- Raw Sockets require elevated privileges: `sudo ./LocalFingerPrint`
- Or grant the capability: `sudo setcap cap_net_raw+ep ./LocalFingerPrint`

**Liquibase migration fails on startup**
- Check database user has `ALTER`, `CREATE`, `DROP` privileges
- If schema is corrupted in dev: set `LIQUIBASE_DROP_FIRST=true` once, restart, then set back to `false`

**`npm install` fails with peer dependency errors**
- Run `npm install --legacy-peer-deps`
