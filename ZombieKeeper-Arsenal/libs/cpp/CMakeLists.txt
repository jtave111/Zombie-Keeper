# =============================================================================
# LIBS/CPP — bibliotecas C++ compartilhadas
# =============================================================================
#
# Para adicionar uma nova lib:
#   1. Crie o diretório: libs/cpp/<nome>/
#   2. Crie o CMakeLists.txt da lib com add_library(<nome> STATIC ...)
#   3. Adicione add_subdirectory(<nome>) abaixo
#
# Qualquer domínio (network-session, agents, ...) pode então usar:
#   target_link_libraries(<meu-target> PRIVATE <nome>)
# =============================================================================

# -----------------------------------------------------------------------------
# Dependências externas — vendored via FetchContent
# -----------------------------------------------------------------------------

include(FetchContent)

# nlohmann/json — serialização JSON header-only (C++17)
# Exporta o target: nlohmann_json::nlohmann_json
FetchContent_Declare(
    nlohmann_json
    URL      https://github.com/nlohmann/json/releases/download/v3.11.3/json.tar.xz
    URL_HASH SHA256=d6c65aca6b1ed68e7a182f4757257b107ae403032760ed6ef121c9d55e81757d
)
set(JSON_BuildTests OFF CACHE BOOL "" FORCE)
set(JSON_Install    OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(nlohmann_json)

# -----------------------------------------------------------------------------
# Libs internas (ordem importa: dependências antes de quem depende delas)
# -----------------------------------------------------------------------------

add_subdirectory(net_utils)        # checksum ICMP — base para ping
add_subdirectory(net_utils/ping)   # ICMP raw socket — sweep de hosts
add_subdirectory(output_utils)     # ZKOutput + JsonSerializer — serialização e log

# -----------------------------------------------------------------------------
# Futuras libs
# -----------------------------------------------------------------------------
# add_subdirectory(crypto)     # wrappers criptográficos
# add_subdirectory(ipc)        # comunicação inter-processo
# add_subdirectory(protocol)   # parsers de protocolo (DNS, HTTP, TLS)
