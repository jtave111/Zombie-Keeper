# =============================================================================
# TARGET: ping  (biblioteca estática)
# =============================================================================
#
# O que é:
#   Biblioteca de baixo nível para envio e recepção de pacotes ICMP Echo.
#   Requer CAP_NET_RAW ou execução como root para abrir raw sockets.
#
# Como usar em qualquer domínio do Arsenal:
#   target_link_libraries(<meu-target> PRIVATE ping)
#   O CMake propaga automaticamente os headers (target_include_directories PUBLIC).
#
# Tipo: STATIC
#   Compilada uma vez e embutida no binário final — sem dependência de .so.
# =============================================================================

add_library(ping STATIC
    Ping.cpp
)

# PUBLIC: quem linkar esta lib herda o diretório de includes automaticamente.
target_include_directories(ping
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/h
)

target_compile_features(ping PUBLIC cxx_std_17)

target_compile_options(ping PRIVATE
    -Wall -Wextra -Wpedantic
)
