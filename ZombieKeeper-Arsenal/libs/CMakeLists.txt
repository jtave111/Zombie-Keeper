# =============================================================================
# LIBS — bibliotecas compartilhadas entre todos os domínios do Arsenal
# =============================================================================
#
# Regra: uma lib entra aqui quando pode ser usada por mais de um domínio.
# Libs exclusivas de um domínio ficam dentro do próprio domínio.
#
# Como adicionar uma nova linguagem (ex: Rust via corrosion):
#   1. Crie libs/rust/CMakeLists.txt
#   2. Adicione add_subdirectory(rust) abaixo
#
# Como adicionar uma nova lib C++:
#   → edite libs/cpp/CMakeLists.txt e adicione add_subdirectory(nova-lib)
# =============================================================================

add_subdirectory(cpp)
add_subdirectory(python)
add_subdirectory(powershell)
add_subdirectory(go)
add_subdirectory(rust)
# add_subdirectory(rust)   # futuro — Rust libs via corrosion
# add_subdirectory(go)     # futuro — Go libs via ExternalProject
