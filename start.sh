#!/bin/bash
# =============================================================================
# ZombieKeeper — Script de inicialização da plataforma
#
# Uso:
#   ./start.sh                  Inicia API + Dashboard Web
#   ./start.sh --build          Recompila a API antes de iniciar
#   ./start.sh --api-only       Inicia somente o servidor API (porta 8080)
#   ./start.sh --web-only       Inicia somente o dashboard Web (porta 3000)
#   ./start.sh --help           Exibe esta ajuda
#
# Pré-requisitos:
#   - Java 21+  (para a API)
#   - Node.js 20+ com npm  (para o Web)
#   - MySQL 8 rodando
#   - ZombieKeeper-Api/.env configurado
# =============================================================================

set -e

PROJECT_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
API_DIR="$PROJECT_ROOT/ZombieKeeper-Api"
WEB_DIR="$PROJECT_ROOT/ZombieKeeper-Web"
API_JAR="$API_DIR/target/Zombie-Keeper-0.0.1-SNAPSHOT.jar"

BUILD=false
API_ONLY=false
WEB_ONLY=false
API_PID=""

# -----------------------------------------------------------------------------
# Parsing de argumentos
# -----------------------------------------------------------------------------
for arg in "$@"; do
    case $arg in
        --build)
            BUILD=true
            ;;
        --api-only)
            API_ONLY=true
            ;;
        --web-only)
            WEB_ONLY=true
            ;;
        --help|-h)
            echo ""
            echo "  Uso: ./start.sh [opções]"
            echo ""
            echo "  Opções:"
            echo "    --build       Recompila a API antes de iniciar"
            echo "    --api-only    Inicia somente o servidor API (porta 8080)"
            echo "    --web-only    Inicia somente o dashboard Web (porta 3000)"
            echo "    --help        Exibe esta mensagem"
            echo ""
            echo "  Para compilar as ferramentas C++ do Arsenal:"
            echo "    cd ZombieKeeper-Arsenal && make"
            echo "    sudo cmake --build ZombieKeeper-Arsenal/build --target setcap"
            echo ""
            exit 0
            ;;
        *)
            echo "[erro] Opção desconhecida: $arg"
            echo "       Execute './start.sh --help' para ver as opções disponíveis."
            exit 1
            ;;
    esac
done

# -----------------------------------------------------------------------------
# Limpeza ao encerrar (Ctrl+C ou SIGTERM)
# -----------------------------------------------------------------------------
cleanup() {
    echo ""
    echo "[*] Encerrando serviços..."

    if [ -n "$API_PID" ] && kill -0 "$API_PID" 2>/dev/null; then
        kill -TERM "$API_PID" 2>/dev/null

        # Aguarda até 10s o shutdown gracioso do Spring Boot
        local waited=0
        while kill -0 "$API_PID" 2>/dev/null && [ $waited -lt 10 ]; do
            sleep 1
            waited=$((waited + 1))
        done

        # Força encerramento se ainda estiver vivo
        if kill -0 "$API_PID" 2>/dev/null; then
            kill -KILL "$API_PID" 2>/dev/null
            echo "[api] Encerrado forçadamente (SIGKILL)."
        else
            echo "[api] Servidor API encerrado."
        fi
    fi

    # Garante que nada ficou na porta mesmo com PID perdido
    local port="${SERVER_PORT:-8080}"
    local zombie
    zombie=$(lsof -ti :"$port" -sTCP:LISTEN 2>/dev/null)
    if [ -n "$zombie" ]; then
        echo "[*] Processo zumbi detectado na porta $port (PID $zombie) — encerrando..."
        kill -KILL "$zombie" 2>/dev/null
    fi

    exit 0
}
trap cleanup SIGINT SIGTERM EXIT

# -----------------------------------------------------------------------------
# Banner
# -----------------------------------------------------------------------------
echo ""
echo "  ╔══════════════════════════════════════╗"
echo "  ║         Z O M B I E K E E P E R      ║"
echo "  ║       Plataforma C2 · Red/Blue Team  ║"
echo "  ╚══════════════════════════════════════╝"
echo ""

# -----------------------------------------------------------------------------
# Carregar variáveis de ambiente da API
# -----------------------------------------------------------------------------
if [ -f "$API_DIR/.env" ]; then
    echo "[env] Carregando $API_DIR/.env"
    set -a
    # shellcheck disable=SC1090
    source "$API_DIR/.env"
    set +a
else
    echo "[aviso] $API_DIR/.env não encontrado — a API pode falhar ao iniciar."
    echo "        Configure o arquivo antes de continuar:"
    echo "        cp ZombieKeeper-Api/.env.example ZombieKeeper-Api/.env"
    echo "        nano ZombieKeeper-Api/.env"
    echo ""
fi

# -----------------------------------------------------------------------------
# Compilar API se solicitado
# -----------------------------------------------------------------------------
if [ "$BUILD" = true ] && [ "$WEB_ONLY" = false ]; then
    echo "[build] Compilando ZombieKeeper-Api..."
    cd "$API_DIR"
    ./mvnw clean package -DskipTests -q
    cd "$PROJECT_ROOT"
    echo "[build] Compilação concluída."
    echo ""
fi

# -----------------------------------------------------------------------------
# Iniciar servidor API
# -----------------------------------------------------------------------------
if [ "$WEB_ONLY" = false ]; then
    if [ ! -f "$API_JAR" ]; then
        echo "[erro] JAR da API não encontrado: $API_JAR"
        echo "       Execute './start.sh --build' para compilar primeiro."
        exit 1
    fi

    echo "[api] Iniciando ZombieKeeper-Api..."
    echo "[api] Endpoint: http://localhost:${SERVER_PORT:-8080}"
    java -jar "$API_JAR" &
    API_PID=$!
    echo "[api] PID: $API_PID"
    echo ""

    # Aguardar a API subir antes de iniciar o Web
    sleep 3
fi

# -----------------------------------------------------------------------------
# Iniciar dashboard Web
# -----------------------------------------------------------------------------
if [ "$API_ONLY" = false ]; then
    if [ ! -d "$WEB_DIR/node_modules" ]; then
        echo "[web] Instalando dependências npm..."
        cd "$WEB_DIR"
        npm install --silent
        cd "$PROJECT_ROOT"
    fi

    echo "[web] Iniciando ZombieKeeper-Web..."
    echo "[web] Dashboard: http://localhost:3000"
    echo ""
    cd "$WEB_DIR"
    npm run dev
else
    # Modo API-only: aguardar o processo da API
    echo "[*] API em execução. Pressione Ctrl+C para encerrar."
    wait "$API_PID"
fi
