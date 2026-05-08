#!/bin/bash

# ZombieKeeper - Startup Script
# Usage: ./start.sh [--build] [--api-only] [--web-only]

set -e

PROJECT_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
API_DIR="$PROJECT_ROOT/ZombieKeeper-Api"
WEB_DIR="$PROJECT_ROOT/ZombieKeeper-Web"
API_JAR="$API_DIR/target/Zombie-Keeper-0.0.1-SNAPSHOT.jar"

BUILD=false
API_ONLY=false
WEB_ONLY=false
API_PID=""

for arg in "$@"; do
    case $arg in
        --build)    BUILD=true ;;
        --api-only) API_ONLY=true ;;
        --web-only) WEB_ONLY=true ;;
        --help|-h)
            echo "Usage: ./start.sh [--build] [--api-only] [--web-only]"
            echo ""
            echo "  --build     Recompile the API before starting"
            echo "  --api-only  Start only the Spring Boot API (port 8080)"
            echo "  --web-only  Start only the Next.js dashboard (port 3000)"
            exit 0
            ;;
        *)
            echo "Unknown option: $arg"
            echo "Run './start.sh --help' for usage."
            exit 1
            ;;
    esac
done

cleanup() {
    echo ""
    echo "Shutting down..."
    if [ -n "$API_PID" ] && kill -0 "$API_PID" 2>/dev/null; then
        kill "$API_PID"
        echo "API server stopped."
    fi
    exit 0
}
trap cleanup SIGINT SIGTERM

echo "========================================="
echo " Zombie Keeper"
echo "========================================="
echo ""

# Load environment variables
if [ -f "$API_DIR/.env" ]; then
    echo "[env] Loading $API_DIR/.env"
    set -a
    # shellcheck disable=SC1090
    source "$API_DIR/.env"
    set +a
else
    echo "[warn] $API_DIR/.env not found — API may fail to start."
    echo "       Copy and configure it before running:"
    echo "       cp ZombieKeeper-Api/.env.example ZombieKeeper-Api/.env"
    echo ""
fi

# Build API if requested
if [ "$BUILD" = true ] && [ "$WEB_ONLY" = false ]; then
    echo "[build] Compiling ZombieKeeper-Api..."
    cd "$API_DIR"
    ./mvnw clean package -DskipTests -q
    cd "$PROJECT_ROOT"
    echo "[build] Done."
    echo ""
fi

# Start API
if [ "$WEB_ONLY" = false ]; then
    if [ ! -f "$API_JAR" ]; then
        echo "[error] API JAR not found: $API_JAR"
        echo "        Run './start.sh --build' to compile first."
        exit 1
    fi

    echo "[api] Starting ZombieKeeper-Api..."
    echo "[api] Endpoint: http://localhost:${SERVER_PORT:-8080}"
    java -jar "$API_JAR" &
    API_PID=$!
    echo "[api] PID: $API_PID"
    echo ""

    # Give the API a moment to bind before starting the web server
    sleep 3
fi

# Start Web dashboard
if [ "$API_ONLY" = false ]; then
    if [ ! -d "$WEB_DIR/node_modules" ]; then
        echo "[web] Installing dependencies..."
        cd "$WEB_DIR"
        npm install --silent
        cd "$PROJECT_ROOT"
    fi

    echo "[web] Starting ZombieKeeper-Web..."
    echo "[web] Dashboard: http://localhost:3000"
    echo ""
    cd "$WEB_DIR"
    npm run dev
else
    # API-only mode: wait for the API process
    echo "API running. Press Ctrl+C to stop."
    wait "$API_PID"
fi
