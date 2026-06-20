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

add_subdirectory(net_utils)  # utilitários compartilhados (checksum ICMP, ...)
add_subdirectory(ping)       # ICMP raw socket — ping/sweep de hosts
add_subdirectory(D_DOS)      # TCP flood + ICMP ping flood (uso autorizado)

# add_subdirectory(crypto)     # futuro — wrappers criptográficos
# add_subdirectory(ipc)        # futuro — comunicação inter-processo
# add_subdirectory(protocol)   # futuro — parsers de protocolo (DNS, HTTP, TLS)
