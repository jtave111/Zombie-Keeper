#!/bin/bash
# =============================================================================
# ZombieKeeper — Script de inicialização da plataforma
#
# Uso:
#   ./ZombieKeeper.sh                  Inicia API + cliente desktop (Tauri dev)
#   ./ZombieKeeper.sh --build          Recompila a API antes de iniciar
#   ./ZombieKeeper.sh --api-only       Inicia somente o servidor API (porta 8080)
#   ./ZombieKeeper.sh --client         Inicia somente o cliente desktop (Tauri dev)
#   ./ZombieKeeper.sh --help           Exibe esta ajuda
#
# Pré-requisitos:
#   - Java 21+        (API)
#   - Rust + cargo    (cliente Tauri)
#   - Node.js 20+     (cliente Tauri)
#   - MySQL 8 rodando
#   - ZombieKeeper-Api/.env configurado
# =============================================================================

set -e

PROJECT_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
API_DIR="$PROJECT_ROOT/ZombieKeeper-Api"
CLIENT_DIR="$PROJECT_ROOT/ZombieKeeper-Client"
API_JAR="$API_DIR/target/Zombie-Keeper-0.0.1-SNAPSHOT.jar"

BUILD=false
API_ONLY=false
CLIENT_ONLY=false
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
        --client)
            CLIENT_ONLY=true
            ;;
        --help|-h)
            echo ""
            echo "  Uso: ./ZombieKeeper.sh [opções]"
            echo ""
            echo "  Opções:"
            echo "    --build       Recompila a API antes de iniciar"
            echo "    --api-only    Inicia somente o servidor API (porta 8080)"
            echo "    --client      Inicia somente o cliente desktop (Tauri dev)"
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
            echo "       Execute './ZombieKeeper.sh --help' para ver as opções disponíveis."
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

        local waited=0
        while kill -0 "$API_PID" 2>/dev/null && [ $waited -lt 10 ]; do
            sleep 1
            waited=$((waited + 1))
        done

        if kill -0 "$API_PID" 2>/dev/null; then
            kill -KILL "$API_PID" 2>/dev/null
            echo "[api] Encerrado forçadamente (SIGKILL)."
        else
            echo "[api] Servidor API encerrado."
        fi
    fi

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
if [ "$BUILD" = true ] && [ "$CLIENT_ONLY" = false ]; then
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
if [ "$CLIENT_ONLY" = false ]; then
    if [ ! -f "$API_JAR" ]; then
        echo "[erro] JAR da API não encontrado: $API_JAR"
        echo "       Execute './ZombieKeeper.sh --build' para compilar primeiro."
        exit 1
    fi

    echo "[api] Iniciando ZombieKeeper-Api..."
    echo "[api] Endpoint: http://localhost:${SERVER_PORT:-8080}"
    java -jar "$API_JAR" &
    API_PID=$!
    echo "[api] PID: $API_PID"
    echo ""

    sleep 3
fi

# -----------------------------------------------------------------------------
# Iniciar cliente desktop (Tauri)
# -----------------------------------------------------------------------------
if [ "$API_ONLY" = false ]; then
    if [ ! -d "$CLIENT_DIR/node_modules" ]; then
        echo "[client] Instalando dependências npm..."
        cd "$CLIENT_DIR"
        npm install --silent
        cd "$PROJECT_ROOT"
    fi

    echo "[client] Iniciando ZombieKeeper-Client (Tauri dev)..."
    echo "[client] A janela do aplicativo será aberta automaticamente."
    echo ""
    cd "$CLIENT_DIR"
    npm run tauri dev
else
    echo "[*] API em execução. Pressione Ctrl+C para encerrar."
    wait "$API_PID"
fi
