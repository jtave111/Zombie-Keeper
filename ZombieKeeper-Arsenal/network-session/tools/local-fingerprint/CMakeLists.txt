# =============================================================================
# TARGET: LocalFingerPrint  (executável)
# =============================================================================
#
# Varredura completa de rede local: ICMP sweep para descoberta de hosts +
# TCP/UDP port scan + serialização JSON + HTTP POST para a API em /api/recon.
#
# Estrutura:
#   include/           ← headers da ferramenta
#   include/model/     ← headers das entidades (Session, Node, Port, Vulnerability)
#   src/               ← implementações
#   src/model/         ← implementações das entidades
#
# Dependências externas:
#   - libcurl          → HTTP POST dos resultados para o C2
#   - ping             → biblioteca interna (raw sockets ICMP)
#
# Como buildar:
#   cmake -B build -DCMAKE_BUILD_TYPE=Debug
#   cmake --build build
#   sudo cmake --build build --target setcap   ← permissão raw socket
#
# Via Makefile do Arsenal:
#   make network-session   (a partir de ZombieKeeper-Arsenal/)
# =============================================================================

cmake_minimum_required(VERSION 3.20)

project(LocalFingerPrint
    VERSION     0.1.0
    DESCRIPTION "Local network fingerprint scanner"
    LANGUAGES   CXX
)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug CACHE STRING "Build type" FORCE)
endif()

# -----------------------------------------------------------------------------
# Dependências externas
# -----------------------------------------------------------------------------
find_package(CURL REQUIRED)

# -----------------------------------------------------------------------------
# Libs internas
# Caminho: network-session/tools/local-fingerprint/ → Arsenal/libs/cpp/
# net_utils deve vir antes de ping (ping linka net_utils).
# -----------------------------------------------------------------------------
add_subdirectory(
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../libs/cpp/net_utils
    ${CMAKE_CURRENT_BINARY_DIR}/libs/net_utils
)
add_subdirectory(
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../libs/cpp/ping
    ${CMAKE_CURRENT_BINARY_DIR}/libs/ping
)

# -----------------------------------------------------------------------------
# Fontes do executável
# -----------------------------------------------------------------------------
add_executable(LocalFingerPrint
    src/main.cpp
    src/App.cpp
    src/FingerprintSession.cpp
    src/SessionBuild.cpp
    src/Scanner.cpp
    src/model/Node.cpp
    src/model/Port.cpp
    src/model/Session.cpp
    src/model/Vulnerability.cpp
)

# -----------------------------------------------------------------------------
# Includes
# Um único ponto de include: include/
# Headers de modelo acessados como: #include "model/Node.h"
# -----------------------------------------------------------------------------
target_include_directories(LocalFingerPrint PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# -----------------------------------------------------------------------------
# Dependências linkadas
# ping exporta seus headers via PUBLIC — herdado automaticamente.
# -----------------------------------------------------------------------------
target_link_libraries(LocalFingerPrint PRIVATE
    ping
    CURL::libcurl
)

target_compile_features(LocalFingerPrint PRIVATE cxx_std_17)

target_compile_options(LocalFingerPrint PRIVATE
    -Wall -Wextra -Wpedantic
)

# -----------------------------------------------------------------------------
# TARGET: setcap — aplica capabilities de raw socket no binário.
# CAP_NET_RAW   → raw sockets (ICMP sweep, TCP scan)
# CAP_NET_ADMIN → configurações de rede de baixo nível
# -----------------------------------------------------------------------------
add_custom_target(setcap
    COMMAND setcap cap_net_raw,cap_net_admin=eip $<TARGET_FILE:LocalFingerPrint>
    DEPENDS LocalFingerPrint
    COMMENT "[*] Aplicando CAP_NET_RAW+CAP_NET_ADMIN ao binário..."
)
