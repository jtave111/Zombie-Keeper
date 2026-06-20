# =============================================================================
# DOMÍNIO: network-session  (Blue Team)
# =============================================================================
#
# Responsabilidade deste arquivo:
#   Agregar todos os targets C/C++ do domínio network-session e declarar
#   dependências externas compartilhadas entre as ferramentas deste domínio.
#
# Ordem de inclusão importa:
#   1. Dependências externas (find_package) — devem ser encontradas antes
#      dos subdirectórios que as usam.
#   2. libs/ — bibliotecas internas compiladas antes dos executáveis.
#   3. scanners/, discovery/, osint/ — ferramentas que dependem das libs.
#
# Como adicionar uma nova ferramenta C/C++:
#   1. Crie o diretório da ferramenta (ex: scanners/service-probe/cpp/)
#   2. Crie o CMakeLists.txt da ferramenta com add_executable(...)
#   3. Adicione add_subdirectory(...) aqui, na seção correta abaixo.
# =============================================================================

# -----------------------------------------------------------------------------
# Dependências externas — resolvidas uma vez para todo o domínio.
# As ferramentas deste domínio usam find_package indiretamente via este nível.
# -----------------------------------------------------------------------------

# libcurl: usada por LocalFingerPrint para HTTP POST dos resultados ao C2.
# REQUIRED: falha o build se não encontrada. Instale com: apt install libcurl4-openssl-dev
find_package(CURL REQUIRED)

# -----------------------------------------------------------------------------
# Scanners — ferramentas de varredura ativa de rede.
# -----------------------------------------------------------------------------
add_subdirectory(tools/local-fingerprint)  # → target: LocalFingerPrint

# -----------------------------------------------------------------------------
# Descoberta de hosts — adicionar quando implementados em C/C++.
# Ferramentas em Python ou Go têm seus próprios sistemas de build.
# -----------------------------------------------------------------------------
# add_subdirectory(discovery/icmp-sweep/cpp)
# add_subdirectory(discovery/arp-scan/cpp)
# add_subdirectory(discovery/dns-enum/cpp)

# -----------------------------------------------------------------------------
# OSINT — adicionar quando implementados em C/C++.
# -----------------------------------------------------------------------------
# add_subdirectory(osint/subdomain/cpp)
