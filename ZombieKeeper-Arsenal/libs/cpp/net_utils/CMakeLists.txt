# =============================================================================
# TARGET: net_utils  (biblioteca estática)
# =============================================================================
#
# Utilitários de rede compartilhados entre todas as libs do Arsenal.
#
# Como usar:
#   target_link_libraries(<meu-target> PRIVATE net_utils)
# =============================================================================

add_library(net_utils STATIC
    checksum/src/checksum.cpp
)

target_include_directories(net_utils
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/checksum/include
)

target_compile_features(net_utils PUBLIC cxx_std_17)

target_compile_options(net_utils PRIVATE
    -Wall -Wextra -Wpedantic
)
