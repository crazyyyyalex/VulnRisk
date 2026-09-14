#!/bin/bash

# VulnRisk Local Development Setup

set -e

DEFAULT_BACKEND_PORT=8000
DEFAULT_FRONTEND_PORT=3000
DEFAULT_DB_PORT=5432

echo "Setting up VulnRisk local development environment..."

echo "Checking prerequisites..."
command -v docker >/dev/null 2>&1 || { echo "Docker is required but not installed."; exit 1; }
command -v docker compose >/dev/null 2>&1 || { echo "Docker Compose is required but not installed."; exit 1; }

if [ ! -f "backend/pyproject.toml" ] || [ ! -f "backend/uv.lock" ]; then
    echo "Please run this script from the VulnRisk root directory."
    exit 1
fi

is_port_in_use() {
    local port=$1
    if command -v lsof >/dev/null 2>&1; then
        lsof -iTCP:"$port" -sTCP:LISTEN -Pn >/dev/null 2>&1
        return $?
    fi
    if command -v nc >/dev/null 2>&1; then
        nc -z localhost "$port" >/dev/null 2>&1
        return $?
    fi
    return 1
}

find_free_port() {
    local start=$1
    local port=$start
    local max=$((start + 100))

    while [ "$port" -lt "$max" ]; do
        if ! is_port_in_use "$port"; then
            echo "$port"
            return 0
        fi
        port=$((port + 1))
    done

    echo "Could not find a free port starting at ${start}." >&2
    return 1
}

read_env_var() {
    local key=$1
    local default=$2
    if [ -f .env ] && grep -q "^${key}=" .env; then
        grep "^${key}=" .env | tail -1 | cut -d= -f2-
    else
        echo "$default"
    fi
}

upsert_env() {
    local key=$1
    local value=$2

    if [ ! -f .env ]; then
        touch .env
    fi

    if grep -q "^${key}=" .env; then
        if [[ "$OSTYPE" == darwin* ]]; then
            sed -i '' "s|^${key}=.*|${key}=${value}|" .env
        else
            sed -i "s|^${key}=.*|${key}=${value}|" .env
        fi
    else
        echo "${key}=${value}" >> .env
    fi
}

ensure_port_available() {
    local var_name=$1
    local current_port=$2
    local default_port=$3
    local label=$4

    if ! is_port_in_use "$current_port"; then
        echo "$current_port"
        return 0
    fi

    echo "Port ${current_port} (${label}) is already in use." >&2
    local free_port
    free_port=$(find_free_port "$default_port")
    echo "Using port ${free_port} for ${label} instead." >&2
    upsert_env "$var_name" "$free_port"
    echo "$free_port"
}

echo "Configuring local environment..."
if [ ! -f .env ]; then
    if [ -f .env.example ]; then
        cp .env.example .env
        echo "Created .env from .env.example"
    else
        touch .env
    fi
else
    echo "Using existing .env (ports and URLs will be validated)"
fi

BACKEND_HOST_PORT=$(read_env_var "BACKEND_HOST_PORT" "$DEFAULT_BACKEND_PORT")
FRONTEND_HOST_PORT=$(read_env_var "FRONTEND_HOST_PORT" "$DEFAULT_FRONTEND_PORT")
DB_HOST_PORT=$(read_env_var "DB_HOST_PORT" "$DEFAULT_DB_PORT")

BACKEND_HOST_PORT=$(ensure_port_available "BACKEND_HOST_PORT" "$BACKEND_HOST_PORT" "$DEFAULT_BACKEND_PORT" "backend")
FRONTEND_HOST_PORT=$(ensure_port_available "FRONTEND_HOST_PORT" "$FRONTEND_HOST_PORT" "$DEFAULT_FRONTEND_PORT" "frontend")
DB_HOST_PORT=$(ensure_port_available "DB_HOST_PORT" "$DB_HOST_PORT" "$DEFAULT_DB_PORT" "database")

upsert_env "BACKEND_HOST_PORT" "$BACKEND_HOST_PORT"
upsert_env "FRONTEND_HOST_PORT" "$FRONTEND_HOST_PORT"
upsert_env "DB_HOST_PORT" "$DB_HOST_PORT"
upsert_env "VITE_API_BASE_URL" "http://localhost:${BACKEND_HOST_PORT}"
upsert_env "DATABASE_URL" "postgresql://vulnrisk:password@localhost:${DB_HOST_PORT}/vulnrisk"

for key in ENVIRONMENT SECRET_KEY DEBUG ENABLE_DEBUG_ENDPOINTS ENABLE_AI_RISK_PREDICTION ENABLE_FEDRAMP_COMPLIANCE; do
    if ! grep -q "^${key}=" .env 2>/dev/null; then
        case "$key" in
            ENVIRONMENT) upsert_env "$key" "development" ;;
            SECRET_KEY) upsert_env "$key" "your-secret-key-here" ;;
            DEBUG) upsert_env "$key" "true" ;;
            ENABLE_DEBUG_ENDPOINTS|ENABLE_AI_RISK_PREDICTION|ENABLE_FEDRAMP_COMPLIANCE)
                upsert_env "$key" "true"
                ;;
        esac
    fi
done

echo "Starting services..."
docker compose up -d

echo "Waiting for services to start..."
sleep 15

echo "Testing setup..."
if curl -s "http://localhost:${BACKEND_HOST_PORT}/health" > /dev/null; then
    echo "Backend is running!"
else
    echo "Backend health check failed"
    echo "Check logs with: docker compose logs backend"
    exit 1
fi

if curl -s "http://localhost:${FRONTEND_HOST_PORT}" > /dev/null; then
    echo "Frontend is running!"
else
    echo "Frontend health check failed"
    echo "Check logs with: docker compose logs frontend"
    exit 1
fi

echo ""
echo "VulnRisk is ready for local development!"
echo ""
echo "Access your application:"
echo "   Frontend: http://localhost:${FRONTEND_HOST_PORT}"
echo "   Backend API: http://localhost:${BACKEND_HOST_PORT}"
echo "   API Docs: http://localhost:${BACKEND_HOST_PORT}/docs"
echo "   Database: localhost:${DB_HOST_PORT}"
echo ""
echo "Port configuration is stored in .env (see .env.example)"
echo ""
echo "Useful commands:"
echo "   View logs: docker compose logs -f"
echo "   Stop services: docker compose down"
echo "   Restart: docker compose restart"
echo "   Reset everything: docker compose down -v && ./setup.sh"
