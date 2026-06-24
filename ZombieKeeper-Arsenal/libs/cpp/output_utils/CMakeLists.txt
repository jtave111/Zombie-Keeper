# =============================================================================
# TARGET: output_utils  (biblioteca estática)
# =============================================================================
#
# Saída padronizada e serialização JSON para os binários do Arsenal.
#
#   ZKOutput       — log estruturado para stderr, resultado JSON para stdout
#   JsonSerializer — serialização das entidades (Session, Node, Port) para JSON
#
# Depende de nlohmann_json::nlohmann_json (FetchContent, declarado em libs/cpp/).
# Quem linkar output_utils herda nlohmann/json.hpp automaticamente (PUBLIC).
#
# Como usar:
#   target_link_libraries(<meu-target> PRIVATE output_utils)
# =============================================================================

add_library(output_utils STATIC
    src/ZKOutput.cpp
    src/JsonSerializer.cpp
)

target_include_directories(output_utils
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    PRIVATE
        # JsonSerializer needs Port/Node types from local-fingerprint
        ${CMAKE_CURRENT_SOURCE_DIR}/../../../network-session/tools/local-fingerprint/include
)

# nlohmann_json::nlohmann_json é INTERFACE — propaga o include path via PUBLIC
target_link_libraries(output_utils
    PUBLIC nlohmann_json::nlohmann_json
)

target_compile_features(output_utils PUBLIC cxx_std_17)

target_compile_options(output_utils PRIVATE
    -Wall -Wextra -Wpedantic
)
