#!/usr/bin/env bash
# =============================================================================
# build-agents.sh
# Compila os targets do domínio agents (implants, exploits, etc.)
#
# Uso:
#   ./scripts/build-agents.sh                        # Debug (padrão)
#   BUILD_TYPE=Release ./scripts/build-agents.sh
#
# Para ativar: adicione targets em agents/CMakeLists.txt e
# descomente add_subdirectory(agents) no CMakeLists.txt raiz.
# =============================================================================
set -e

ARSENAL_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUILD_DIR="$ARSENAL_ROOT/build"
BUILD_TYPE="${BUILD_TYPE:-Debug}"

echo "[!] Domínio agents ainda não tem targets C/C++ configurados."
echo "    Adicione ferramentas em agents/ e ative no CMakeLists.txt raiz."
