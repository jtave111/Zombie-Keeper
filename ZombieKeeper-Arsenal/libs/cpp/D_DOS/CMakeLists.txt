# =============================================================================
# TARGET: D_DOS  (biblioteca estática)
# =============================================================================
#
# Ferramenta de stress test de rede para uso autorizado em pentests.
# TCP flood e ICMP ping flood via raw sockets.
# Requer CAP_NET_RAW para ping_flood.
#
# Como usar:
#   target_link_libraries(<meu-target> PRIVATE D_DOS)
# =============================================================================

add_library(D_DOS STATIC
    src/DOS.cpp
)

target_include_directories(D_DOS
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(D_DOS PRIVATE net_utils)

target_compile_features(D_DOS PUBLIC cxx_std_17)

target_compile_options(D_DOS PRIVATE
    -Wall -Wextra -Wpedantic
)
