
# =============================================================================
# ZOMBIEKEEPER ARSENAL — CMakeLists.txt raiz
# =============================================================================
#
# Este é o entry point do projeto para CMake e para o CLion.
# Abrir este arquivo no CLion equivale a abrir o projeto inteiro.
#
# ESTRUTURA DE BUILD
# ==================
#
#   ZombieKeeper-Arsenal/           ← você está aqui (project root)
#   └── build/                      ← diretório de build (fora do source)
#       ├── compile_commands.json   ← gerado automaticamente (clangd, VSCode)
#       ├── libs/
#       │   └── cpp/
#       │       └── ping/
#       │           └── libping.a              ← lib estática compartilhada
#       ├── network-session/
#       │   └── scanners/
#       │       └── local-fingerprint/
#       │           └── cpp/
#       │               └── LocalFingerPrint   ← binário compilado
#       └── agents/                 ← futuro
#
# COMO BUILDAR
# ============
#
#   Configurar (uma vez, ou ao mudar CMakeLists.txt):
#       cmake -B build -DCMAKE_BUILD_TYPE=Debug
#
#   Compilar tudo:
#       cmake --build build
#
#   Compilar target específico:
#       cmake --build build --target LocalFingerPrint
#       cmake --build build --target ping
#
#   Limpar artefatos:
#       cmake --build build --target clean
#       # ou para reset completo:
#       rm -rf build/
#
#   Build de release (otimizado, sem símbolos de debug):
#       cmake -B build -DCMAKE_BUILD_TYPE=Release
#       cmake --build build
#
# BUILD TYPES DISPONÍVEIS
# =======================
#   Debug   (padrão) → -g -O0     → símbolos de debug, sem otimização
#   Release          → -O3 -DNDEBUG → otimizado para produção/deploy
#   RelWithDebInfo   → -O2 -g     → otimizado com símbolos (profiling)
#
# COMO ABRIR NO CLION
# ===================
#   File → Open → selecionar esta pasta (ZombieKeeper-Arsenal/)
#   CLion detecta este CMakeLists.txt e configura o projeto automaticamente.
#   Todos os targets (LocalFingerPrint, ping) aparecem no seletor de Run/Debug.
#
# COMPILE_COMMANDS.JSON (clangd / VSCode)
# ========================================
#   Gerado automaticamente em build/compile_commands.json.
#   Para usar com VSCode ou clangd, crie um symlink na raiz:
#       ln -s build/compile_commands.json compile_commands.json
#   O .gitignore já ignora o arquivo na raiz para evitar versionamento.
#
# COMO ADICIONAR UMA NOVA LIB COMPARTILHADA
# ==========================================
#   1. Crie libs/cpp/<nome>/ com o CMakeLists.txt e fontes
#   2. Adicione add_subdirectory(<nome>) em libs/cpp/CMakeLists.txt
#   3. Re-execute: cmake -B build
#   Qualquer domínio pode então usar: target_link_libraries(<target> PRIVATE <nome>)
#
# COMO ADICIONAR UM NOVO DOMÍNIO (ex: agents/)
# ============================================
#   1. Crie agents/CMakeLists.txt com find_package + add_subdirectory das ferramentas
#   2. Descomente a linha add_subdirectory(agents) abaixo
#   3. Re-execute: cmake -B build
# =============================================================================

cmake_minimum_required(VERSION 3.20)

project(ZombieKeeper-Arsenal
    VERSION     0.1.0
    DESCRIPTION "ZombieKeeper offensive/defensive tool arsenal"
    LANGUAGES   CXX
)

# -----------------------------------------------------------------------------
# Gera compile_commands.json em build/ automaticamente.
# Usado por clangd (VSCode IntelliSense, CLion externo, Neovim LSP, etc.)
# -----------------------------------------------------------------------------
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# -----------------------------------------------------------------------------
# Build type padrão: Debug quando não especificado.
# Em CI/CD, passe -DCMAKE_BUILD_TYPE=Release explicitamente.
# -----------------------------------------------------------------------------
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug CACHE STRING "Build type" FORCE)
endif()

message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "Compiler:   ${CMAKE_CXX_COMPILER}")

# -----------------------------------------------------------------------------
# Libs compartilhadas — carregadas ANTES dos domínios para que os targets
# estejam disponíveis quando os domínios chamarem target_link_libraries.
# -----------------------------------------------------------------------------

add_subdirectory(libs)

# -----------------------------------------------------------------------------
# Domínios ativos — cada domínio tem seu próprio CMakeLists.txt que
# agrega as ferramentas e declara dependências externas do domínio.
# -----------------------------------------------------------------------------

add_subdirectory(network-session)   # Blue team: scanners, discovery, osint

# Descomente conforme os domínios forem sendo desenvolvidos:
# add_subdirectory(agents)          # Red team: implants, exploits, post-exploitation
