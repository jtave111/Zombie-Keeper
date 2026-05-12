# ZombieKeeper — Referência Rápida para Desenvolvedores

Referência de configuração, comandos e resolução de problemas da plataforma ZombieKeeper.

---

## Pré-requisitos

| Ferramenta | Versão | Instalação |
|---|---|---|
| Java JDK | 21+ | [adoptium.net](https://adoptium.net/) |
| Maven | 3.8+ | Incluído via wrapper `mvnw` |
| Node.js | 20+ | [nodejs.org](https://nodejs.org/) |
| MySQL | 8+ | `apt install mysql-server` |
| GCC/G++ | 11+ (C++17) | `apt install build-essential` |
| CMake | 3.20+ | `apt install cmake` |
| libcurl (dev) | qualquer | `apt install libcurl4-openssl-dev` |
| Python | 3.10+ | `apt install python3` |

> Raw Sockets exigem **root ou `CAP_NET_RAW`** no host que executa o agente C++.

---

## Configuração de Ambiente

### Servidor API (`ZombieKeeper-Api/.env`)

Crie este arquivo antes de iniciar a API. Ele é gitignored — **nunca commite credenciais**.

```env
# Banco de dados
DB_HOST=localhost
DB_PORT=3306
DB_NAME=c2_db
DB_USERNAME=root
DB_PASSWORD=sua_senha
DB_URL=jdbc:mysql://${DB_HOST}:${DB_PORT}/${DB_NAME}?createDatabaseIfNotExist=true&useSSL=false&allowPublicKeyRetrieval=true&serverTimezone=UTC

# JWT
JWT_SECRET=sua-chave-secreta-com-pelo-menos-32-caracteres
JWT_EXPIRATION=86400000
JWT_REFRESH_EXPIRATION=604800000

# Servidor
SERVER_PORT=8080
SERVER_ADDRESS=0.0.0.0

# CORS (deve incluir a origem do dashboard web)
CORS_ALLOWED_ORIGINS=http://localhost:3000,http://localhost:8080
CORS_ALLOWED_METHODS=GET,POST,PUT,DELETE,PATCH,OPTIONS
CORS_ALLOWED_HEADERS=*
CORS_ALLOW_CREDENTIALS=true

# Liquibase
LIQUIBASE_ENABLED=true
LIQUIBASE_DROP_FIRST=false

# Conta admin padrão (criada na primeira execução)
ADMIN_USERNAME=admin
ADMIN_PASSWORD=TroqueMinhaSenha!2024
ADMIN_EMAIL=admin@zombiekeeper.local

# Perfil Spring
SPRING_PROFILES_ACTIVE=dev

# Upload de arquivos (Loot)
FILE_UPLOAD_DIR=./uploads
FILE_MAX_SIZE=10485760

# Configuração C2
C2_AGENT_TIMEOUT=300000
C2_HEARTBEAT_INTERVAL=60000
C2_MAX_AGENTS=1000

# Chaves de API externas (opcionais)
NVD_API_KEY=
SHODAN_API_KEY=
VIRUSTOTAL_API_KEY=
```

### Dashboard Web (`ZombieKeeper-Web/.env.local`)

```env
NEXT_PUBLIC_API_URL=http://localhost:8080
```

---

## Endpoints da API

URL base: `http://localhost:8080`

Autenticação: `Authorization: Bearer <jwt_token>`

### Autenticação

| Método | Caminho | Auth | Descrição |
|---|---|---|---|
| `POST` | `/api/auth/login` | Não | Login e obtenção do token JWT |
| `GET` | `/api/auth/users` | Admin | Listar todos os operadores |
| `POST` | `/api/auth/register` | Admin | Criar novo operador |
| `PUT` | `/api/auth/users/{id}/role` | Admin | Atualizar role do operador |
| `PUT` | `/api/auth/users/{id}/password` | Admin | Alterar senha do operador |
| `DELETE` | `/api/auth/users/{id}` | Admin | Remover operador |
| `GET` | `/api/auth/roles` | Admin | Listar roles disponíveis |

**Exemplo de login:**
```bash
curl -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"TroqueMinhaSenha!2024"}'
```

### Agents (Red Team)

| Método | Caminho | Descrição |
|---|---|---|
| `GET` | `/api/c2-server/agents` | Listar todos os agents registrados |
| `GET` | `/api/c2-server/agents/{id}` | Obter agent por ID |
| `POST` | `/api/c2-server/agents/register` | Registrar novo agent (chamado pelo implant) |
| `PUT` | `/api/c2-server/agents/{id}/ping` | Atualizar heartbeat do agent |
| `PUT` | `/api/c2-server/agents/{id}/delete` | Soft-delete do agent |
| `GET` | `/api/c2-server/info` | Informações e estatísticas do servidor C2 |

### Recon — Network Session (Blue Team)

| Método | Caminho | Descrição |
|---|---|---|
| `GET` | `/c2-server/local-network/recon/session/{binary}/{flag}/{sec}/{usec}` | Executar scan completo da subnet |
| `GET` | `/c2-server/local-network/recon/node/{binary}/{mac}/{netId}/{flag}/{sec}/{usec}` | Re-scan de host específico |
| `GET` | `/c2-server/local-network/recon/node/{binary}/{netId}/{mac}/{ip}/{port}/{sec}/{usec}` | Scan de porta específica |
| `GET` | `/c2-server/local-network/recon/automation/python/start-recon/{script}` | Iniciar automação Python (async) |
| `DELETE` | `/c2-server/local-network/recon/automation/python/stop/{script}` | Parar processo Python |
| `DELETE` | `/admin/reset-database` | Reset completo do banco (dev only) |

---

## Configuração do Banco de Dados

A API usa **MySQL 8** com **Liquibase** para migrações de schema. O banco é criado automaticamente se não existir (requer `createDatabaseIfNotExist=true` na URL JDBC).

```sql
-- Criar o banco manualmente se necessário
CREATE DATABASE c2_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
```

O Liquibase executa as migrações na inicialização. Para resetar o schema (apenas em dev):

```env
LIQUIBASE_DROP_FIRST=true
```

> Volte para `false` após o reset para evitar apagar dados na próxima reinicialização.

---

## Tarefas Comuns de Desenvolvimento

### Executar API em modo desenvolvimento

```bash
cd ZombieKeeper-Api
./mvnw spring-boot:run
```

### Executar Web em modo desenvolvimento

```bash
cd ZombieKeeper-Web
npm run dev
```

### Executar verificação de tipos completa (Web)

```bash
cd ZombieKeeper-Web
npx tsc --noEmit
```

### Build JAR de produção

```bash
cd ZombieKeeper-Api
./mvnw clean package -DskipTests
```

### Build Web de produção

```bash
cd ZombieKeeper-Web
npm run build
npm start
```

### Compilar ferramentas C++ do Arsenal

```bash
cd ZombieKeeper-Arsenal

# Instalar dependências (primeira vez)
sudo apt install build-essential cmake libcurl4-openssl-dev

# Configurar e compilar (Debug)
cmake -B build -DCMAKE_BUILD_TYPE=Debug -DCMAKE_EXPORT_COMPILE_COMMANDS=ON .
cmake --build build

# Ou via Makefile wrapper:
make              # Debug
make release      # Release (otimizado)

# Compilar target específico
cmake --build build --target LocalFingerPrint
cmake --build build --target ping

# Limpar artefatos (mantém configuração cmake)
make clean

# Reset completo (remove build/ inteiro)
make reset
```

### Aplicar capabilities de rede ao binário

O binário precisa de `CAP_NET_RAW` para abrir raw sockets (ICMP + TCP scan):

```bash
# Aplicar via cmake target (recomendado)
sudo cmake --build build --target setcap

# Ou diretamente
sudo setcap cap_net_raw,cap_net_admin=eip \
  ZombieKeeper-Arsenal/build/network-session/scanners/local-fingerprint/cpp/LocalFingerPrint
```

### Executar o scanner de rede

```bash
# O binário fica em build/, não na raiz do Arsenal
sudo ZombieKeeper-Arsenal/build/network-session/scanners/local-fingerprint/cpp/LocalFingerPrint
```

### Integrar com CLion

1. Abrir o CLion
2. `File → Open` → selecionar `ZombieKeeper-Arsenal/`
3. CLion detecta o `CMakeLists.txt` raiz automaticamente
4. Targets disponíveis no seletor: `LocalFingerPrint`, `ping`, `setcap`
5. Run/Debug funcionam com breakpoints nativos (GDB/LLDB)

### Gerar compile_commands.json (para VSCode / clangd)

O arquivo é gerado automaticamente em `build/compile_commands.json` pelo cmake. Para usar com VSCode ou clangd na raiz:

```bash
cd ZombieKeeper-Arsenal
ln -sf build/compile_commands.json compile_commands.json
```

---

## Notas do Projeto

- **Nome do pacote:** A aplicação Spring Boot usa `com.manager.Zombie_Keeper` (underscore) porque `com.manager.Zombie-Keeper` não é um nome de pacote Java válido.
- **Armazenamento do token:** O dashboard web armazena o JWT no `localStorage` com a chave `zk_token`.
- **Polling de agents:** O dashboard faz polling em `/api/c2-server/agents` a cada 30 segundos via `setInterval`.
- **Map SSR:** O mapa mundial Leaflet (`WorldMap.tsx`) usa `next/dynamic` com `ssr: false` porque o Leaflet requer o DOM do browser.
- **CORS:** O `CorsConfig` da API deve incluir a origem do dashboard. Atualize `CORS_ALLOWED_ORIGINS` ao fazer deploy em hosts/portas diferentes.
- **Liquibase:** As migrações ficam em `src/main/resources/db/changelog/`. Não edite o schema do banco manualmente — sempre adicione um novo changeset.
- **CMake build directory:** O Arsenal usa build out-of-source em `ZombieKeeper-Arsenal/build/`. Nunca commite este diretório (já no `.gitignore`).
- **Caminhos de deploy do Arsenal:** A API busca os binários em `modules/linux/c++/code/localFingerPrint/` relativo ao diretório do JAR. Atualize `LocalNetworkFingerprintService.java` ao mudar o local de deploy do binário compilado.

---

## Solução de Problemas

**API não inicia — "DB connection refused"**
- Verifique se o MySQL está rodando: `sudo systemctl start mysql`
- Confirme `DB_HOST`, `DB_PORT`, `DB_USERNAME`, `DB_PASSWORD` no `.env`

**Web exibe "Network Error" / "Failed to fetch"**
- Confirme que a API está rodando em `http://localhost:8080`
- Verifique `NEXT_PUBLIC_API_URL` em `ZombieKeeper-Web/.env.local`
- Verifique se `CORS_ALLOWED_ORIGINS` inclui `http://localhost:3000`

**Scanner C++ falha com "Operation not permitted"**
- Raw Sockets exigem privileges elevadas — aplique capabilities:
  ```bash
  sudo cmake --build ZombieKeeper-Arsenal/build --target setcap
  ```
- Ou rode com sudo: `sudo ./LocalFingerPrint`

**cmake não encontra libcurl**
- Instale os headers de desenvolvimento:
  ```bash
  sudo apt install libcurl4-openssl-dev
  ```
- Se o mirror estiver com 404, baixe direto do Debian:
  ```bash
  wget https://ftp.debian.org/debian/pool/main/libc/libcurl4/libcurl4-openssl-dev_<versão>_amd64.deb
  sudo dpkg -i libcurl4-openssl-dev_*.deb
  sudo apt --fix-broken install
  ```

**Migração Liquibase falha na inicialização**
- Verifique se o usuário do banco tem privilégios `ALTER`, `CREATE`, `DROP`
- Se o schema estiver corrompido em dev: defina `LIQUIBASE_DROP_FIRST=true` uma vez, reinicie, depois volte para `false`

**`npm install` falha com erros de peer dependency**
- Execute: `npm install --legacy-peer-deps`

**CLion não detecta targets do Arsenal**
- Certifique-se de abrir a pasta `ZombieKeeper-Arsenal/` (que contém `CMakeLists.txt`), não uma subpasta
- Caso o CMake não configure: `Tools → CMake → Reset Cache and Reload Project`
