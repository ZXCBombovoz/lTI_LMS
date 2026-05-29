#!/usr/bin/env bash
# =============================================================================
# MTUCI Labs — установка зависимостей + запуск на VPS (Linux)
# =============================================================================
# Использование:
#     ./run.sh                          # установка зависимостей и запуск
#     PORT=8080 ./run.sh                # на другом порту
#     ./run.sh stop                     # остановить
#     ./run.sh logs                     # смотреть логи
#     ./run.sh restart                  # перезапустить
#     ./run.sh rebuild                  # полная пересборка
#     ./run.sh status                   # статус контейнера
# =============================================================================
set -e

IMAGE="mtuci-labs:latest"
CONTAINER="mtuci-labs"

# Цветной вывод (только в TTY)
if [ -t 1 ]; then
  G='\033[0;32m'; Y='\033[1;33m'; R='\033[0;31m'; B='\033[0;34m'; N='\033[0m'
else
  G=''; Y=''; R=''; B=''; N=''
fi
info() { printf "${G}[info]${N} %s\n" "$*"; }
warn() { printf "${Y}[warn]${N} %s\n" "$*"; }
err()  { printf "${R}[err ]${N} %s\n" "$*"; }
step() { printf "\n${B}==>${N} ${B}%s${N}\n" "$*"; }

# sudo если не root
SUDO=""
if [ "$EUID" -ne 0 ]; then
  if command -v sudo >/dev/null 2>&1; then
    SUDO="sudo"
  else
    err "Не root и нет sudo — установка пакетов невозможна"
    exit 1
  fi
fi

# -----------------------------------------------------------------------------
# Команда compose: пробуем docker compose (v2), потом docker-compose (v1)
# -----------------------------------------------------------------------------
detect_compose() {
  if docker compose version >/dev/null 2>&1; then
    echo "docker compose"
  elif command -v docker-compose >/dev/null 2>&1; then
    echo "docker-compose"
  else
    echo ""
  fi
}

# -----------------------------------------------------------------------------
# Управляющие команды
# -----------------------------------------------------------------------------
case "${1:-}" in
  stop)
    info "Останавливаю контейнер..."
    COMPOSE=$(detect_compose)
    if [ -n "$COMPOSE" ] && [ -f docker-compose.yml ]; then
      $COMPOSE down
    else
      docker stop "$CONTAINER" 2>/dev/null && info "Остановлено" || warn "Контейнер не запущен"
    fi
    exit 0
    ;;
  logs)
    docker logs -f "$CONTAINER"
    exit 0
    ;;
  restart)
    info "Перезапускаю..."
    docker restart "$CONTAINER"
    exit 0
    ;;
  status)
    docker ps -a --filter "name=$CONTAINER" --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
    exit 0
    ;;
  rebuild)
    info "Полная пересборка..."
    COMPOSE=$(detect_compose)
    if [ -n "$COMPOSE" ] && [ -f docker-compose.yml ]; then
      $COMPOSE down 2>/dev/null || true
    fi
    docker stop "$CONTAINER" 2>/dev/null || true
    docker rm   "$CONTAINER" 2>/dev/null || true
    docker rmi  "$IMAGE"     2>/dev/null || true
    ;;
esac

# -----------------------------------------------------------------------------
# Шаг 1: установка Docker если нет
# -----------------------------------------------------------------------------
if ! command -v docker >/dev/null 2>&1; then
  step "Docker не найден, устанавливаю..."

  if [ -f /etc/debian_version ]; then
    DISTRO="$(. /etc/os-release && echo "$ID")"
    CODENAME="$(. /etc/os-release && echo "$VERSION_CODENAME")"

    $SUDO apt-get update -y
    $SUDO apt-get install -y --no-install-recommends \
      ca-certificates curl gnupg lsb-release

    $SUDO install -m 0755 -d /etc/apt/keyrings
    if [ ! -f /etc/apt/keyrings/docker.gpg ]; then
      curl -fsSL "https://download.docker.com/linux/${DISTRO}/gpg" \
        | $SUDO gpg --dearmor -o /etc/apt/keyrings/docker.gpg
      $SUDO chmod a+r /etc/apt/keyrings/docker.gpg
    fi
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/${DISTRO} ${CODENAME} stable" \
      | $SUDO tee /etc/apt/sources.list.d/docker.list >/dev/null
    $SUDO apt-get update -y
    $SUDO apt-get install -y --no-install-recommends \
      docker-ce docker-ce-cli containerd.io \
      docker-buildx-plugin docker-compose-plugin

  elif [ -f /etc/redhat-release ] || [ -f /etc/rocky-release ] || [ -f /etc/almalinux-release ] || [ -f /etc/fedora-release ]; then
    if command -v dnf >/dev/null 2>&1; then PKG=dnf; else PKG=yum; fi
    $SUDO $PKG install -y dnf-plugins-core 2>/dev/null || $SUDO $PKG install -y yum-utils
    $SUDO $PKG config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo 2>/dev/null \
      || $SUDO yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
    $SUDO $PKG install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

  elif [ -f /etc/arch-release ]; then
    $SUDO pacman -Sy --noconfirm docker docker-compose

  elif [ -f /etc/alpine-release ]; then
    $SUDO apk add --no-cache docker docker-compose

  else
    err "Неизвестный дистрибутив. Установите Docker вручную:"
    err "  https://docs.docker.com/engine/install/"
    exit 1
  fi

  info "Docker установлен."
fi

# -----------------------------------------------------------------------------
# Шаг 2: запуск daemon
# -----------------------------------------------------------------------------
if ! docker info >/dev/null 2>&1; then
  step "Запускаю Docker daemon..."
  $SUDO systemctl enable --now docker 2>/dev/null \
    || $SUDO service docker start 2>/dev/null \
    || true
  sleep 2
  if ! docker info >/dev/null 2>&1; then
    err "Не удалось запустить Docker daemon. Запустите вручную:"
    err "  sudo systemctl start docker"
    exit 1
  fi
fi

# Если docker не доступен без sudo — будем использовать sudo
DOCKER="docker"
if ! docker ps >/dev/null 2>&1; then
  warn "Текущий пользователь не в группе docker."
  warn "Чтобы не использовать sudo каждый раз:"
  warn "  sudo usermod -aG docker \$USER && newgrp docker"
  DOCKER="$SUDO docker"
fi

# -----------------------------------------------------------------------------
# Шаг 3: .env
# -----------------------------------------------------------------------------
if [ ! -f .env ]; then
  if [ -f .env.example ]; then
    step ".env не найден"
    cp .env.example .env
    warn "Создан .env из шаблона .env.example"
    warn ""
    warn "ОБЯЗАТЕЛЬНО отредактируйте .env перед запуском в production:"
    warn "  - VITE_APP_URL  (публичный URL вашего инструмента)"
    warn "  - LTI_PRIVATE_KEY (приватный ключ инструмента)"
    warn "  - LAB_FLAG_SECRET (секрет для генерации флагов)"
    warn "  - и т.д. (см. комментарии в .env)"
    warn ""
    read -r -p "Открыть .env в редакторе сейчас? [Y/n] " yn
    if [[ ! "$yn" =~ ^[Nn] ]]; then
      ${EDITOR:-nano} .env
    fi
  else
    warn ".env не найден и .env.example отсутствует — запуск без env-переменных"
  fi
fi

# -----------------------------------------------------------------------------
# Шаг 4: сборка и запуск
# -----------------------------------------------------------------------------
COMPOSE=$(detect_compose)

if [ -n "$COMPOSE" ] && [ -f docker-compose.yml ]; then
  step "Запускаю через $COMPOSE..."

  # Переопределение порта через переменную окружения PORT
  if [ -n "${PORT:-}" ]; then
    export HTTP_PORT="$PORT"
  fi

  $COMPOSE up -d --build

  # Получим финальный порт
  HTTP_PORT="${PORT:-$(grep -E '^HTTP_PORT=' .env 2>/dev/null | cut -d= -f2 || echo 3000)}"
else
  step "docker compose не найден, использую обычный docker..."

  $DOCKER build -t "$IMAGE" .

  $DOCKER stop "$CONTAINER" 2>/dev/null || true
  $DOCKER rm   "$CONTAINER" 2>/dev/null || true

  HTTP_PORT="${PORT:-$(grep -E '^HTTP_PORT=' .env 2>/dev/null | cut -d= -f2 || echo 3000)}"
  ENV_OPT=""
  [ -f .env ] && ENV_OPT="--env-file .env"

  $DOCKER run -d \
    --name "$CONTAINER" \
    -p "${HTTP_PORT}:3000" \
    --restart unless-stopped \
    $ENV_OPT \
    "$IMAGE" >/dev/null
fi

# -----------------------------------------------------------------------------
# Шаг 5: проверка
# -----------------------------------------------------------------------------
sleep 3
if $DOCKER ps --format '{{.Names}}' | grep -q "^${CONTAINER}$"; then
  info ""
  info "════════════════════════════════════════════════════════════"
  info "  Готово! Откройте: http://localhost:${HTTP_PORT}"
  info "════════════════════════════════════════════════════════════"
  info ""
  info "  Логи:           ./run.sh logs"
  info "  Стоп:           ./run.sh stop"
  info "  Перезапуск:     ./run.sh restart"
  info "  Пересборка:     ./run.sh rebuild"
  info "  Статус:         ./run.sh status"
  info ""
  info "  Для production-доступа через домен настройте reverse"
  info "  proxy (nginx/Caddy) на хосте — пример в .env.example."
else
  err "Контейнер не запустился. Последние логи:"
  $DOCKER logs "$CONTAINER" 2>&1 | tail -50
  exit 1
fi
