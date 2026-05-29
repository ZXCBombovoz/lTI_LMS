# =============================================================================
# MTUCI Labs — автономный образ для VPS-деплоя
# =============================================================================
# Никаких внешних зависимостей кроме Docker.
# Vercel не используется. Все сервисы внутри одного контейнера:
#   - Node 20 (Express + статика + TS API handlers)
#   - Python 3 (serverless-функция api/index.py для /labs/*)
# =============================================================================
FROM node:20-bullseye

USER root
ENV NPM_CONFIG_UNSAFE_PERM=true \
    NPM_CONFIG_AUDIT=false \
    NPM_CONFIG_FUND=false \
    NODE_ENV=production \
    DEBIAN_FRONTEND=noninteractive

# Системные зависимости: Python 3 + базовые утилиты
RUN apt-get update && apt-get install -y --no-install-recommends \
      python3 python3-pip ca-certificates curl \
    && ln -sf /usr/bin/python3 /usr/local/bin/python \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# 1) Зависимости фронта (отдельным слоем для кэша)
COPY package*.json ./
RUN npm install --unsafe-perm

# 2) Серверные зависимости (Express + proxy + esbuild для bundling TS)
RUN npm install --no-save --unsafe-perm \
      express@^4.19.2 \
      http-proxy-middleware@^2.0.6 \
      esbuild@^0.20.0

# 3) Копируем проект (node_modules исключён через .dockerignore)
COPY . .

# 4) Сборка фронта Vite → dist/
RUN npm run build

# 5) Бандлим TypeScript API handlers в CJS
RUN mkdir -p dist-api && \
    for f in api/*.ts; do \
      name=$(basename "$f" .ts); \
      ./node_modules/.bin/esbuild "$f" \
        --bundle --platform=node \
        --outfile="dist-api/${name}.cjs" --format=cjs \
        --external:@vercel/node --log-level=warning; \
    done

EXPOSE 3000

# Один процесс Node поднимает Python child и Express
CMD ["node", "server.cjs"]
