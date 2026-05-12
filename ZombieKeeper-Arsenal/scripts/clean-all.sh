#!/usr/bin/env bash
# =============================================================================
# clean-all.sh
# Remove o diretório build/ inteiro (reset completo do cmake).
# Após executar, o próximo build reconfigura e recompila tudo do zero.
# =============================================================================
set -e

ARSENAL_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUILD_DIR="$ARSENAL_ROOT/build"

if [ -d "$BUILD_DIR" ]; then
    rm -rf "$BUILD_DIR"
    echo "[*] $BUILD_DIR removido."
else
    echo "[*] Nada para limpar — $BUILD_DIR não existe."
fi
