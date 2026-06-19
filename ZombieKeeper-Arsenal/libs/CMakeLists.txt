# =============================================================================
# LIBS — bibliotecas C/C++ compartilhadas entre os módulos do Arsenal
# =============================================================================
#
# Apenas bibliotecas C/C++ ficam aqui — cada linguagem tem seu próprio
# sistema de build (go.mod para Go, Cargo.toml para Rust, etc).
#
# Como adicionar uma nova lib C++:
#   1. Crie libs/cpp/<nome>/ com CMakeLists.txt e fontes
#   2. Adicione add_subdirectory(<nome>) em libs/cpp/CMakeLists.txt
# =============================================================================

add_subdirectory(cpp)
