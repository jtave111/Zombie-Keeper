#!/usr/bin/env bash
# =============================================================================
# build-all.sh
# Configura e compila todos os domínios do Arsenal via cmake.
#
# Uso:
#   ./scripts/build-all.sh                           # Debug (padrão)
#   BUILD_TYPE=Release ./scripts/build-all.sh
# =============================================================================
set -e

ARSENAL_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUILD_DIR="$ARSENAL_ROOT/build"
BUILD_TYPE="${BUILD_TYPE:-Debug}"

echo "[*] ZombieKeeper Arsenal — build completo"
echo "    Root:       $ARSENAL_ROOT"
echo "    Build dir:  $BUILD_DIR"
echo "    Build type: $BUILD_TYPE"
echo ""

cmake -B "$BUILD_DIR" \
    -DCMAKE_BUILD_TYPE="$BUILD_TYPE" \
    -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
    "$ARSENAL_ROOT"

cmake --build "$BUILD_DIR" --parallel

echo ""
echo "[+] Build completo."
