# =============================================================================
# ZombieKeeper Arsenal — Makefile raiz (wrapper CMake)
# =============================================================================
#
# Este Makefile é um wrapper de conveniência sobre o CMake.
# Use-o para builds rápidos via terminal ou CI/CD sem precisar
# lembrar os comandos cmake completos.
#
# O sistema de build real é o CMake (CMakeLists.txt na raiz).
# Para uso avançado (targets específicos, flags customizadas),
# use cmake diretamente — veja os comentários no CMakeLists.txt raiz.
#
# TARGETS DISPONÍVEIS
# ===================
#   make              → configura (se necessário) e compila tudo em Debug
#   make release      → compila tudo em Release (otimizado)
#   make network-session → compila apenas o domínio network-session
#   make agents       → compila apenas o domínio agents (quando disponível)
#   make clean        → remove artefatos de build (mantém configuração cmake)
#   make reset        → remove o diretório build/ inteiro (reset completo)
#   make help         → exibe esta ajuda
# =============================================================================

BUILD_DIR := build
BUILD_TYPE ?= Debug

.PHONY: all release network-session agents clean reset help

# Configura o cmake na primeira execução (ou se build/ não existir),
# depois compila tudo.
all: $(BUILD_DIR)/CMakeCache.txt
	@cmake --build $(BUILD_DIR) --parallel

release:
	@cmake -B $(BUILD_DIR) -DCMAKE_BUILD_TYPE=Release -DCMAKE_EXPORT_COMPILE_COMMANDS=ON
	@cmake --build $(BUILD_DIR) --parallel

# Compila apenas o target LocalFingerPrint (e sua dependência ping).
network-session: $(BUILD_DIR)/CMakeCache.txt
	@cmake --build $(BUILD_DIR) --target LocalFingerPrint --parallel

# Placeholder — ativar quando agents/CMakeLists.txt for criado.
agents:
	@echo "[!] Domínio agents ainda não tem targets C/C++ configurados."

clean:
	@cmake --build $(BUILD_DIR) --target clean 2>/dev/null || true
	@echo "[*] Artefatos removidos. Configuração cmake mantida em $(BUILD_DIR)/."

# Reset completo: remove tudo incluindo a configuração cmake.
# Após reset, o próximo 'make' reconfigura do zero.
reset:
	@rm -rf $(BUILD_DIR)
	@echo "[*] $(BUILD_DIR)/ removido. Execute 'make' para reconfigurar."

help:
	@echo ""
	@echo "  make              build Debug (padrão)"
	@echo "  make release      build Release (otimizado)"
	@echo "  make network-session  apenas ferramentas de network-session"
	@echo "  make clean        remove artefatos, mantém config cmake"
	@echo "  make reset        remove build/ inteiro"
	@echo ""
	@echo "  Build type manual:"
	@echo "    cmake -B build -DCMAKE_BUILD_TYPE=Debug|Release|RelWithDebInfo"
	@echo "    cmake --build build --target <nome-do-target>"
	@echo ""
	@echo "  Targets disponíveis: LocalFingerPrint, ping"
	@echo ""

# Configura o cmake se build/ ainda não existir ou se algum CMakeLists.txt mudou.
$(BUILD_DIR)/CMakeCache.txt: CMakeLists.txt network-session/CMakeLists.txt
	@cmake -B $(BUILD_DIR) -DCMAKE_BUILD_TYPE=$(BUILD_TYPE) -DCMAKE_EXPORT_COMPILE_COMMANDS=ON
