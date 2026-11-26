FROM oven/bun:1-alpine AS builder
WORKDIR /app

COPY package.json bun.lock* ./
RUN bun install

COPY tsconfig.json tsconfig.test.json ./
COPY src ./src
COPY scripts ./scripts
RUN bun run check:zero-orm && bun run build

FROM oven/bun:1-alpine AS runtime
WORKDIR /app
ENV NODE_ENV=production
ENV ROCKSOUL_CORE_PORT=4520
ENV ROCKSOUL_CORE_HOST=0.0.0.0

COPY --from=builder /app/package.json ./package.json
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/scripts ./scripts

EXPOSE 4520

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD bun -e "fetch('http://127.0.0.1:' + (process.env.ROCKSOUL_CORE_PORT || '4520') + '/health').then(r => process.exit(r.ok ? 0 : 1)).catch(() => process.exit(1))"

CMD ["bun", "dist/src/server.js"]
