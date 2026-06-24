# =============================================================================
# TARGET: dos  (biblioteca estática)
# =============================================================================
#
# Ferramenta de stress test de rede para uso autorizado em pentests.
# TCP flood e ICMP ping flood via raw sockets.
# Requer CAP_NET_RAW para ping_flood.
#
# Suporta build standalone (a partir deste diretório) e build via root.
#
# Como usar:
#   target_link_libraries(<meu-target> PRIVATE dos)
# =============================================================================

# net_utils: adicionada aqui apenas em build standalone.
# Em build via root do Arsenal já estará definida.
if(NOT TARGET net_utils)
    add_subdirectory(
        ${CMAKE_CURRENT_SOURCE_DIR}/../../../../libs/cpp/net_utils
        ${CMAKE_CURRENT_BINARY_DIR}/libs/net_utils
    )
endif()

add_library(dos STATIC
    src/DOS.cpp
)

target_include_directories(dos
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(dos PRIVATE net_utils)

target_compile_features(dos PUBLIC cxx_std_17)

target_compile_options(dos PRIVATE
    -Wall -Wextra -Wpedantic
)
