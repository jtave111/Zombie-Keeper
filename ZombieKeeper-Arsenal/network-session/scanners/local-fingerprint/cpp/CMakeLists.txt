# =============================================================================
# TARGET: LocalFingerPrint  (executável)
# =============================================================================
#
# O que faz:
#   Varredura completa de rede local: ICMP sweep para descoberta de hosts +
#   TCP port scan via raw sockets + serialização JSON + HTTP POST para a
#   API em /api/recon.
#
# Dependências externas:
#   - libcurl  →  HTTP POST dos resultados para o C2
#   - ping     →  biblioteca interna (raw sockets ICMP)
#
# Permissão especial:
#   Raw sockets exigem CAP_NET_RAW. Após o build, o CMake executa setcap
#   automaticamente (requer sudo ou ambiente com a capability configurada).
#   Ver step POST_BUILD abaixo.
#
# Como buildar (linha de comando):
#   cmake -B build -DCMAKE_BUILD_TYPE=Debug
#   cmake --build build
#   O binário será gerado em:  build/network-session/scanners/local-fingerprint/cpp/LocalFingerPrint
#
# Como buildar no CLion:
#   File → Open → selecionar ZombieKeeper-Arsenal/CMakeLists.txt (raiz)
#   CLion detecta este target automaticamente. Run/Debug funcionam direto.
# =============================================================================

# Requer que o CMakeLists.txt pai já tenha chamado find_package(CURL)
# antes de entrar neste subdiretório (feito no CMakeLists.txt de network-session/).

# -----------------------------------------------------------------------------
# Fontes do executável — listadas explicitamente (boa prática CMake).
# Ao adicionar um novo .cpp, inclua aqui e re-execute cmake.
# -----------------------------------------------------------------------------
add_executable(LocalFingerPrint
    localNetwork/app/main.cpp
    localNetwork/app/App.cpp
    localNetwork/FingerPrintSession.cpp
    localNetwork/SessionBuild.cpp
    localNetwork/model/Node.cpp
    localNetwork/model/Port.cpp
    localNetwork/model/Session.cpp
    localNetwork/model/Vulnerability.cpp
    localNetwork/scanners/Scanner.cpp
)

# -----------------------------------------------------------------------------
# Includes — cada módulo tem headers em subdiretório h/
# PRIVATE: esses paths são apenas para compilar este executável,
#          não propagados para quem linkar este target.
# -----------------------------------------------------------------------------
target_include_directories(LocalFingerPrint PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}                          # raiz do cpp/
    ${CMAKE_CURRENT_SOURCE_DIR}/localNetwork/h           # FingerprintSession.h, SessionBuild.h
    ${CMAKE_CURRENT_SOURCE_DIR}/localNetwork/app/h       # App.h
    ${CMAKE_CURRENT_SOURCE_DIR}/localNetwork/model/h     # Node.h, Port.h, Session.h, Vulnerability.h
    ${CMAKE_CURRENT_SOURCE_DIR}/localNetwork/scanners/h  # Scanner.h
)

# -----------------------------------------------------------------------------
# Dependências linkadas
#
#   ping       →  target interno definido em libs/cpp/ping/ (raiz do Arsenal).
#                 O CMake já sabe onde estão os headers (propagação PUBLIC).
#
#   CURL::libcurl → target importado pelo find_package(CURL) no nível acima.
#                   Linka libcurl e inclui curl/curl.h automaticamente.
# -----------------------------------------------------------------------------
target_link_libraries(LocalFingerPrint PRIVATE
    ping
    CURL::libcurl
)

# Padrão C++17 herdado da lib ping (PUBLIC), mas declarado aqui também
# para deixar explícito o requisito deste target.
target_compile_features(LocalFingerPrint PRIVATE cxx_std_17)

target_compile_options(LocalFingerPrint PRIVATE
    -Wall -Wextra -Wpedantic
)

# -----------------------------------------------------------------------------
# TARGET: setcap — aplica capabilities de raw socket no binário.
#
# Separado do build principal porque exige sudo com terminal interativo.
# O cmake --build normal compila o binário sem bloquear em senha.
#
# Como usar após o build:
#   sudo cmake --build build --target setcap
#   # ou diretamente:
#   sudo setcap cap_net_raw,cap_net_admin=eip <caminho>/LocalFingerPrint
#
# CAP_NET_RAW   → permite abrir raw sockets (ICMP sweep, TCP scan)
# CAP_NET_ADMIN → permite configurações de rede de baixo nível
# =eip          → effective, inheritable, permitted
#
# Em CI/CD sem terminal interativo, configure sudoers para setcap sem senha:
#   echo "runner ALL=(ALL) NOPASSWD: /sbin/setcap" >> /etc/sudoers
# -----------------------------------------------------------------------------
add_custom_target(setcap
    COMMAND setcap cap_net_raw,cap_net_admin=eip $<TARGET_FILE:LocalFingerPrint>
    DEPENDS LocalFingerPrint
    COMMENT "[*] Aplicando CAP_NET_RAW+CAP_NET_ADMIN ao binário LocalFingerPrint..."
)
