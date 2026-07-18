# --- Build stage ---
FROM node:20-alpine AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY tsconfig.json ./
COPY src/ ./src/
RUN npm run build

# --- Production stage ---
FROM node:20-alpine
WORKDIR /app
ENV NODE_ENV=production
ENV LIMEKEY_CONFIG=/etc/limekey/config.yaml

COPY package.json package-lock.json ./
RUN npm ci --omit=dev

COPY --from=build /app/dist ./dist
COPY policies/ ./policies/
COPY limekey.config.example.yaml ./limekey.config.example.yaml

# Copy and setup entrypoint script
COPY docker-entrypoint.sh ./
RUN chmod +x docker-entrypoint.sh

# Create the default configuration and audit log directories
RUN mkdir -p /etc/limekey /app/audit && \
    chown -R node:node /etc/limekey /app/audit

EXPOSE 8443

HEALTHCHECK --interval=10s --timeout=5s --start-period=5s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:8443/health || exit 1

USER node
ENTRYPOINT ["/app/docker-entrypoint.sh"]
