#!/usr/bin/env bash
# =============================================================================
# build-network-session.sh
# Compila apenas os targets do domínio network-session.
#
# Uso:
#   ./scripts/build-network-session.sh               # Debug (padrão)
#   BUILD_TYPE=Release ./scripts/build-network-session.sh
# =============================================================================
set -e

ARSENAL_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUILD_DIR="$ARSENAL_ROOT/build"
BUILD_TYPE="${BUILD_TYPE:-Debug}"

echo "[*] Configurando cmake (build type: $BUILD_TYPE)..."
cmake -B "$BUILD_DIR" \
    -DCMAKE_BUILD_TYPE="$BUILD_TYPE" \
    -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
    "$ARSENAL_ROOT"

echo "[*] Compilando LocalFingerPrint..."
cmake --build "$BUILD_DIR" --target LocalFingerPrint --parallel

BINARY="$BUILD_DIR/network-session/scanners/local-fingerprint/cpp/LocalFingerPrint"
if [ -f "$BINARY" ]; then
    echo "[+] Binário gerado: $BINARY"
else
    echo "[-] Binário não encontrado em $BINARY"
    exit 1
fi
