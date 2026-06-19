# =============================================================================
# ZombieKeeper Automations — Makefile
# =============================================================================
#
# Wrapper de conveniência para tarefas comuns de desenvolvimento.
#
# TARGETS DISPONÍVEIS
# ===================
#   make setup     → cria virtualenv e instala dependências
#   make test      → executa todos os testes
#   make lint      → verifica estilo e tipos (quando configurado)
#   make clean     → remove cache Python e artefatos de build
#   make help      → exibe esta ajuda
# =============================================================================

VENV    := .venv
PYTHON  := $(VENV)/bin/python
PIP     := $(VENV)/bin/pip
PYTEST  := $(VENV)/bin/pytest

.PHONY: setup test lint clean help

# Cria o virtualenv e instala dependências de dev
setup: $(VENV)/bin/activate

$(VENV)/bin/activate:
	@echo "[*] Criando virtualenv em $(VENV)/"
	@python3 -m venv $(VENV)
	@$(PIP) install --quiet --upgrade pip
	@$(PIP) install --quiet -e ".[dev]"
	@echo "[+] Ambiente pronto. Ative com: source $(VENV)/bin/activate"

# Executa todos os testes
test: $(VENV)/bin/activate
	@$(PYTEST) tests/ -v

# Lint — descomentar quando ruff/mypy estiver em pyproject.toml
# lint: $(VENV)/bin/activate
# 	@$(VENV)/bin/ruff check .
# 	@$(VENV)/bin/mypy .

# Remove cache e artefatos
clean:
	@find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	@find . -type f -name "*.pyc" -delete 2>/dev/null || true
	@rm -rf .pytest_cache .coverage htmlcov dist build *.egg-info
	@echo "[*] Cache limpo."

help:
	@echo ""
	@echo "  make setup   cria virtualenv e instala dependências"
	@echo "  make test    executa os testes com pytest"
	@echo "  make clean   remove cache e artefatos"
	@echo ""
	@echo "  Ativar ambiente: source .venv/bin/activate"
	@echo "  Rodar script:   python scripts/<nome>.py"
	@echo ""
