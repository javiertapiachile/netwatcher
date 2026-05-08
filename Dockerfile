# ── Etapa de dependencias ─────────────────────────────────────
FROM node:22-alpine AS deps

WORKDIR /app

# sqlite3 necesita python3 y make para compilar en Alpine
RUN apk add --no-cache python3 make g++

COPY package.json ./
RUN npm install --omit=dev

# ── Etapa de producción ───────────────────────────────────────
FROM node:22-alpine AS runtime

WORKDIR /app

RUN addgroup -S netwatch && adduser -S netwatch -G netwatch

COPY --from=deps /app/node_modules ./node_modules
COPY src/     ./src/
COPY public/  ./public/
COPY package.json ./

RUN mkdir -p /app/data && chown -R netwatch:netwatch /app/data

ENV NODE_ENV=production \
    PORT=3000 \
    HOST=0.0.0.0 \
    DB_PATH=/app/data/netwatch.db

USER netwatch
EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget -qO- http://localhost:3000/api/v1/stats || exit 1

CMD ["node", "src/server.js"]
