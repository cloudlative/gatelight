# syntax=docker/dockerfile:1
FROM node:22-alpine AS deps
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --no-audit --no-fund

FROM node:22-alpine
LABEL org.opencontainers.image.title="GateLight" \
      org.opencontainers.image.source="https://github.com/Cloudlative/gatelight" \
      org.opencontainers.image.vendor="Cloudlative" \
      org.opencontainers.image.description="See your HAProxy and NGINX as a map: relationships, live health, config audit" \
      org.opencontainers.image.licenses="MIT"
ENV NODE_ENV=production PORT=3000
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY package.json server.js ./
COPY src ./src
COPY public ./public
COPY examples ./examples
# Unprivileged runtime user; configs are mounted read-only at /app/config.
# /app/data holds instances added from the UI (mount a volume here so they survive upgrades).
RUN mkdir -p /app/data && chown node:node /app/data
USER node
EXPOSE 3000
HEALTHCHECK --interval=30s --timeout=4s --start-period=10s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:'+process.env.PORT+'/healthz').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
CMD ["node", "server.js"]
