# ZombieKeeper Arsenal — Guia de Build e Scripts

Referência completa para compilar, executar e manter as ferramentas nativas do Arsenal.

---

## Sumário

1. [Estrutura do Arsenal](#estrutura)
2. [Pré-requisitos](#pré-requisitos)
3. [Primeira execução (setup inicial)](#primeira-execução)
4. [Fluxo de build do dia a dia](#fluxo-de-build)
5. [Referência dos scripts](#referência-dos-scripts)
6. [Referência do Makefile](#referência-do-makefile)
7. [Comandos cmake diretos](#comandos-cmake-diretos)
8. [Aplicar capabilities de rede (setcap)](#setcap)
9. [Onde ficam os binários](#onde-ficam-os-binários)
10. [Uso no CLion](#uso-no-clion)
11. [Adicionando uma nova lib compartilhada](#adicionando-uma-nova-lib-compartilhada)
12. [Adicionando uma nova ferramenta](#adicionando-uma-nova-ferramenta)

---

## Estrutura

```
ZombieKeeper-Arsenal/
├── CMakeLists.txt                      ← entry point do CMake / CLion
├── Makefile                            ← wrapper de conveniência sobre o cmake
├── scripts/                            ← scripts de automação de build
│   ├── build-all.sh
│   ├── build-network-session.sh
│   ├── build-agents.sh
│   └── clean-all.sh
│
├── libs/                               ← bibliotecas compartilhadas entre domínios
│   ├── CMakeLists.txt
│   └── cpp/
│       ├── CMakeLists.txt
│       └── ping/                       ← biblioteca estática ICMP (libping.a)
│           ├── CMakeLists.txt
│           ├── h/Ping.h
│           └── Ping.cpp
│
├── network-session/                    ← domínio Blue Team
│   ├── CMakeLists.txt
│   └── scanners/
│       └── local-fingerprint/
│           └── cpp/                   ← LocalFingerPrint (binário)
│               ├── CMakeLists.txt
│               └── *.cpp
│
└── agents/                             ← domínio Red Team (futuro)

build/                                  ← gerado pelo cmake (não versionado)
├── compile_commands.json               ← IntelliSense do clangd / VSCode
├── libs/
│   └── cpp/
│       └── ping/
│           └── libping.a               ← biblioteca estática compilada
└── network-session/
    └── scanners/local-fingerprint/cpp/
        └── LocalFingerPrint            ← binário final
```

**Domínios:**
- `libs` — bibliotecas C++ compartilhadas entre todos os domínios. Toda lib que pode ser usada por mais de um domínio vive aqui.
- `network-session` — ferramentas Blue Team: scanners, descoberta de rede, fingerprinting. Alimentam o modelo `NetworkSession → Node → Port → Vulnerability` da API.
- `agents` — ferramentas Red Team: implants, loaders, post-exploitation. Alimentarão o modelo `Agent → Loot` da API.

---

## Pré-requisitos

Instale uma única vez no host de desenvolvimento:

```bash
sudo apt install build-essential cmake libcurl4-openssl-dev
```

| Ferramenta | Versão mínima | Verificar |
|---|---|---|
| GCC / G++ | 11+ (C++17) | `g++ --version` |
| CMake | 3.20+ | `cmake --version` |
| libcurl (headers) | qualquer | `dpkg -l libcurl4-openssl-dev` |

> **Parrot OS / mirrors quebrados:** se o `apt install` falhar com 404, baixe os pacotes diretamente do Debian:
> ```bash
> # libgssrpc (dependência do libcurl-dev)
> wget https://ftp.debian.org/debian/pool/main/k/krb5/libgssrpc4t64_1.21.3-5_amd64.deb
> sudo dpkg -i libgssrpc4t64_1.21.3-5_amd64.deb
>
> # libtasn1-6-dev (dependência do libcurl-dev)
> wget https://ftp.debian.org/debian/pool/main/libt/libtasn1-6/libtasn1-6-dev_4.20.0-2_amd64.deb
> sudo dpkg -i libtasn1-6-dev_4.20.0-2_amd64.deb
>
> sudo apt --fix-broken install
> sudo apt install libcurl4-openssl-dev
> ```

---

## Primeira Execução

Execute estes passos **uma única vez** ao clonar o repositório ou ao limpar o build:

```bash
# 1. Entre na raiz do Arsenal
cd ZombieKeeper-Arsenal

# 2. Configure o cmake e compile tudo
./scripts/build-all.sh

# 3. Aplique capabilities de rede ao binário (exige sudo)
sudo cmake --build build --target setcap
```

Após isso o binário `build/network-session/scanners/local-fingerprint/cpp/LocalFingerPrint`
está pronto para uso.

---

## Fluxo de Build

### Reconstruir após alterar código

```bash
cd ZombieKeeper-Arsenal

# Opção A — via Makefile (mais curto)
make

# Opção B — via script
./scripts/build-all.sh

# Opção C — cmake direto
cmake --build build --parallel
```

O cmake é incremental: só recompila os arquivos que mudaram.

### Só o domínio network-session mudou

```bash
make network-session
# ou
./scripts/build-network-session.sh
# ou
cmake --build build --target LocalFingerPrint --parallel
```

### Build de Release (produção / deploy)

```bash
# Via Makefile
make release

# Via script
BUILD_TYPE=Release ./scripts/build-all.sh

# Via cmake
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
```

### Limpar e recomeçar

```bash
# Limpar artefatos mas manter configuração cmake (rebuild rápido)
make clean

# Reset total — remove build/ inteiro (próximo make reconfigura do zero)
make reset
# ou
./scripts/clean-all.sh
```

---

## Referência dos Scripts

Todos os scripts ficam em `scripts/` e devem ser executados **a partir da raiz do Arsenal**:

```bash
cd ZombieKeeper-Arsenal
./scripts/<nome>.sh
```

---

### `build-all.sh`

**Quando usar:** setup inicial, depois de `clean-all.sh`, ou quando múltiplos domínios foram alterados.

```bash
./scripts/build-all.sh                        # Debug (padrão)
BUILD_TYPE=Release ./scripts/build-all.sh     # Release
BUILD_TYPE=RelWithDebInfo ./scripts/build-all.sh  # Release com símbolos de debug
```

O que ele faz, passo a passo:
1. Resolve o caminho absoluto do Arsenal (`ARSENAL_ROOT`)
2. Executa `cmake -B build -DCMAKE_BUILD_TYPE=... -DCMAKE_EXPORT_COMPILE_COMMANDS=ON .` — gera `build/` e `build/compile_commands.json`
3. Executa `cmake --build build --parallel` — compila todos os targets ativos (libs + ferramentas)

---

### `build-network-session.sh`

**Quando usar:** apenas ferramentas do domínio Blue Team foram alteradas.

```bash
./scripts/build-network-session.sh                        # Debug
BUILD_TYPE=Release ./scripts/build-network-session.sh     # Release
```

O que ele faz:
1. Configura o cmake (se `build/` ainda não existir)
2. Compila apenas o target `LocalFingerPrint` (a lib `ping` é recompilada automaticamente se necessário)
3. Verifica se o binário foi gerado e imprime o caminho

Saída esperada:
```
[*] Configurando cmake (build type: Debug)...
[*] Compilando LocalFingerPrint...
[+] Binário gerado: /home/.../ZombieKeeper-Arsenal/build/network-session/scanners/local-fingerprint/cpp/LocalFingerPrint
```

---

### `build-agents.sh`

**Quando usar:** quando ferramentas Red Team forem adicionadas ao domínio `agents/`.

```bash
./scripts/build-agents.sh
```

Atualmente imprime um aviso informando que o domínio ainda não tem targets configurados. Nenhum build é executado.

Para ativar:
1. Adicione targets em `agents/CMakeLists.txt`
2. Descomente `add_subdirectory(agents)` no `CMakeLists.txt` raiz
3. Atualize `build-agents.sh` para incluir os targets

---

### `clean-all.sh`

**Quando usar:** para forçar uma reconfiguração completa do cmake (mudança de compilador, flags globais, atualização do CMakeLists.txt raiz).

```bash
./scripts/clean-all.sh
```

O que ele faz: remove o diretório `build/` inteiro com `rm -rf`.

> **Atenção:** `make clean` (sem reset) remove só os `.o` e binários mas mantém a configuração cmake — use-o para rebuildos incrementais. `clean-all.sh` / `make reset` remove tudo e é mais lento pois refaz a configuração.

---

## Referência do Makefile

O `Makefile` na raiz do Arsenal é um wrapper sobre o cmake. Use-o quando preferir comandos curtos no terminal.

```bash
cd ZombieKeeper-Arsenal

make                  # configura (se necessário) e compila tudo em Debug
make release          # compila tudo em Release (otimizado, -O3)
make network-session  # compila apenas LocalFingerPrint + ping
make agents           # placeholder — imprime aviso até o domínio ser configurado
make clean            # remove binários/objetos, mantém configuração cmake
make reset            # remove build/ inteiro (equivalente a clean-all.sh)
make help             # exibe todos os targets disponíveis
```

---

## Comandos CMake Diretos

Para controle total sobre o build sem passar pelo Makefile ou scripts:

```bash
cd ZombieKeeper-Arsenal

# ── Configuração ──────────────────────────────────────────────────────────────

# Debug (padrão)
cmake -B build -DCMAKE_BUILD_TYPE=Debug -DCMAKE_EXPORT_COMPILE_COMMANDS=ON .

# Release
cmake -B build -DCMAKE_BUILD_TYPE=Release -DCMAKE_EXPORT_COMPILE_COMMANDS=ON .

# RelWithDebInfo (release otimizado com símbolos — útil para profiling)
cmake -B build -DCMAKE_BUILD_TYPE=RelWithDebInfo -DCMAKE_EXPORT_COMPILE_COMMANDS=ON .


# ── Build ─────────────────────────────────────────────────────────────────────

cmake --build build --parallel               # todos os targets
cmake --build build --target LocalFingerPrint # só LocalFingerPrint
cmake --build build --target ping            # só a lib ping
cmake --build build --target clean           # limpa artefatos (mantém config)


# ── Capabilities ─────────────────────────────────────────────────────────────

sudo cmake --build build --target setcap     # aplica CAP_NET_RAW ao binário


# ── Limpeza ───────────────────────────────────────────────────────────────────

cmake --build build --target clean           # remove .o e binários
rm -rf build/                                # reset total
```

---

## Setcap

O `LocalFingerPrint` abre **raw sockets** (ICMP + TCP SYN scan) — isso exige privilégios elevados.

Há duas formas de executar:

**Opção 1 — setcap (recomendada para desenvolvimento)**

Aplica as capabilities `CAP_NET_RAW` e `CAP_NET_ADMIN` diretamente no binário. Após isso o binário roda sem sudo:

```bash
sudo cmake --build build --target setcap
```

Precisa ser refeito **toda vez que o binário for recompilado** (o linker gera um novo inode e o kernel limpa as capabilities).

**Opção 2 — sudo (alternativa rápida)**

```bash
sudo build/network-session/scanners/local-fingerprint/cpp/LocalFingerPrint
```

---

## Onde Ficam os Binários

Todos os artefatos ficam dentro de `build/` (nunca na raiz do Arsenal):

```
build/
├── libs/
│   └── cpp/
│       └── ping/
│           └── libping.a                   ← biblioteca estática compartilhada
└── network-session/
    └── scanners/
        └── local-fingerprint/
            └── cpp/
                └── LocalFingerPrint        ← binário executável
```

Caminho completo a partir da raiz do monorepo:
```
ZombieKeeper-Arsenal/build/network-session/scanners/local-fingerprint/cpp/LocalFingerPrint
```

> Este é o caminho que a API usa para invocar o scanner. Se o local mudar, atualize `LocalNetworkFingerprintService.java`.

---

## Uso no CLion

1. `File → Open` → selecione a pasta `ZombieKeeper-Arsenal/` (que contém o `CMakeLists.txt`)
2. O CLion detecta o `CMakeLists.txt` raiz automaticamente e configura o projeto
3. Targets disponíveis no seletor Run/Debug: `LocalFingerPrint`, `ping`, `setcap`
4. Run/Debug com breakpoints nativos (GDB/LLDB) funcionam diretamente

**IntelliSense / clangd no VSCode:**

O `compile_commands.json` é gerado automaticamente em `build/compile_commands.json`. Para ativá-lo no VSCode, crie um symlink na raiz do Arsenal:

```bash
cd ZombieKeeper-Arsenal
ln -sf build/compile_commands.json compile_commands.json
```

O `.gitignore` já exclui este symlink do versionamento.

---

## Adicionando uma Nova Lib Compartilhada

Quando uma lib pode ser usada por mais de um domínio (network-session, agents, etc.), ela deve ficar em `libs/`.

### Nova lib C++

1. Crie a pasta e os arquivos:
   ```
   libs/cpp/<nome>/
   ├── CMakeLists.txt
   ├── h/<Nome>.h
   └── <Nome>.cpp
   ```

2. `libs/cpp/<nome>/CMakeLists.txt` mínimo:
   ```cmake
   add_library(<nome> STATIC <Nome>.cpp)
   target_include_directories(<nome> PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/h)
   target_compile_features(<nome> PUBLIC cxx_std_17)
   ```

3. Registre em `libs/cpp/CMakeLists.txt`:
   ```cmake
   add_subdirectory(<nome>)
   ```

4. Use em qualquer domínio:
   ```cmake
   target_link_libraries(MinhaFerramenta PRIVATE <nome>)
   ```

---

## Adicionando uma Nova Ferramenta

### No domínio `network-session`

1. Crie a pasta da ferramenta com o sufixo de linguagem:
   ```
   network-session/scanners/<nome-da-ferramenta>/cpp/
   ```

2. Adicione um `CMakeLists.txt` mínimo:
   ```cmake
   add_executable(NomeDaFerramenta
       main.cpp
       Ferramenta.cpp
   )
   target_compile_features(NomeDaFerramenta PRIVATE cxx_std_17)
   target_compile_options(NomeDaFerramenta PRIVATE -Wall -Wextra)
   # libs compartilhadas disponíveis automaticamente:
   target_link_libraries(NomeDaFerramenta PRIVATE ping CURL::libcurl)
   ```

3. Adicione `add_subdirectory(scanners/<nome>/cpp)` no `network-session/CMakeLists.txt`

4. Recompile:
   ```bash
   cmake -B build  # reconfigura
   cmake --build build --target NomeDaFerramenta
   ```

### No domínio `agents`

1. Descomente `add_subdirectory(agents)` no `CMakeLists.txt` raiz
2. Crie `agents/<nome-do-implant>/cpp/` (ou `rust/`, `go/`, etc.)
3. Adicione o `CMakeLists.txt` da ferramenta
4. Registre o `add_subdirectory` em `agents/CMakeLists.txt`
5. Atualize `scripts/build-agents.sh` com o target correto

Libs compartilhadas de `libs/` estão automaticamente disponíveis para o domínio `agents` via `target_link_libraries`.
