# =============================================================================
# ZombieKeeper Arsenal — Makefile raiz (coordenador polyglot)
# =============================================================================
#
# Ponto de entrada único para buildar qualquer ferramenta do Arsenal.
# Cada linguagem tem seu próprio sistema de build — este Makefile orquestra.
#
#   C/C++    → CMake  (cada módulo tem seu próprio CMakeLists.txt autossuficiente)
#   Go       → go build  (cada módulo tem seu go.mod)
#   Rust     → cargo build  (cada módulo tem seu Cargo.toml)
#   Python   → sem build — executar direto com python3
#   Assembly → nasm  (por módulo)
#
# Não existe CMakeLists.txt na raiz do Arsenal.
# Cada módulo C++ é autossuficiente e pode ser aberto no CLion diretamente.
#
# TARGETS DISPONÍVEIS
# ===================
#   make                  → builda tudo (toolchains ativos)
#   make network-session  → builda LocalFingerPrint
#   make go               → builda módulos Go ativos
#   make rust             → builda módulos Rust ativos
#   make release          → build Release otimizado
#   make clean            → remove artefatos de build
#   make help             → exibe esta ajuda
# =============================================================================

BUILD_TYPE ?= Debug

# Diretório de build de cada módulo C++ (dentro do próprio módulo)
BUILD_NS := network-session/tools/local-fingerprint/build

# ─── Detecta toolchains disponíveis ──────────────────────────────────────────
HAS_CMAKE := $(shell command -v cmake 2>/dev/null)
HAS_GO    := $(shell command -v go    2>/dev/null)
HAS_CARGO := $(shell command -v cargo 2>/dev/null)
HAS_NASM  := $(shell command -v nasm  2>/dev/null)

.PHONY: all network-session go rust release clean help

# ─── Build de tudo ───────────────────────────────────────────────────────────
all: network-session
# Descomentar conforme módulos Go/Rust forem sendo ativados:
# all: network-session go rust

# ─── C/C++: network-session/LocalFingerPrint ─────────────────────────────────
network-session: $(BUILD_NS)/CMakeCache.txt
ifndef HAS_CMAKE
	$(error "[!] cmake não encontrado. Instale: sudo apt install cmake")
endif
	@cmake --build $(BUILD_NS) --parallel

$(BUILD_NS)/CMakeCache.txt:
	@cmake \
		-B $(BUILD_NS) \
		-S network-session/tools/local-fingerprint \
		-DCMAKE_BUILD_TYPE=$(BUILD_TYPE) \
		-DCMAKE_EXPORT_COMPILE_COMMANDS=ON

# ─── Go ──────────────────────────────────────────────────────────────────────
go:
ifndef HAS_GO
	$(error "[!] go não encontrado. Instale: https://go.dev/dl/")
endif
	@echo "[*] Nenhum módulo Go ativo ainda."
# Exemplo — descomentar quando o módulo existir:
# @cd agents/implants/linux/go && go build -o ../../../../build/linux-implant ./...

# ─── Rust ────────────────────────────────────────────────────────────────────
rust:
ifndef HAS_CARGO
	$(error "[!] cargo não encontrado. Instale: https://rustup.rs/")
endif
	@echo "[*] Nenhum módulo Rust ativo ainda."
# Exemplo — descomentar quando o módulo existir:
# @cd agents/implants/linux/rust && cargo build --release

# ─── Release ─────────────────────────────────────────────────────────────────
release:
	@$(MAKE) BUILD_TYPE=Release network-session

# ─── Limpeza ─────────────────────────────────────────────────────────────────
clean:
	@rm -rf $(BUILD_NS)
	@find . -name "target" -path "*/rust/target" -exec rm -rf {} + 2>/dev/null || true
	@echo "[*] Artefatos removidos."

# ─── Help ────────────────────────────────────────────────────────────────────
help:
	@echo ""
	@echo "  make                  build tudo (toolchains ativos)"
	@echo "  make network-session  build LocalFingerPrint (C++)"
	@echo "  make go               build módulos Go"
	@echo "  make rust             build módulos Rust"
	@echo "  make release          build Release otimizado"
	@echo "  make clean            remove artefatos de build"
	@echo ""
	@echo "  Toolchains detectados:"
	@echo "    cmake : $(if $(HAS_CMAKE),OK,NÃO ENCONTRADO)"
	@echo "    go    : $(if $(HAS_GO),OK,NÃO ENCONTRADO)"
	@echo "    cargo : $(if $(HAS_CARGO),OK,NÃO ENCONTRADO)"
	@echo "    nasm  : $(if $(HAS_NASM),OK,NÃO ENCONTRADO)"
	@echo ""
	@echo "  Abrir no CLion:"
	@echo "    LocalFingerPrint → abrir: network-session/scanners/local-fingerprint/cpp/"
	@echo ""
