# ── Stage 1: deps ─────────────────────────────────────────────
FROM node:20-slim AS deps
WORKDIR /app
COPY backend/package.json .
ENV PUPPETEER_SKIP_DOWNLOAD=1
RUN npm install --omit=dev

# ── Stage 2: runtime ──────────────────────────────────────────
FROM node:20-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl tar ca-certificates chromium php-cli php-mbstring php-zip unzip git fonts-liberation fonts-noto \
    python3 python3-pip \
    && rm -rf /var/lib/apt/lists/* \
    && pip3 install semgrep --break-system-packages --quiet





ARG TRIVY_VERSION=0.58.2
RUN curl -sL "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz" \
    | tar -xz -C /usr/local/bin trivy && trivy --version

ARG GRYPE_VERSION=0.88.0
RUN curl -sL "https://github.com/anchore/grype/releases/download/v${GRYPE_VERSION}/grype_${GRYPE_VERSION}_linux_amd64.tar.gz" \
    | tar -xz -C /usr/local/bin grype && grype version

# Install Composer (needed for Packagist dependency resolution)
RUN curl -sS https://getcomposer.org/installer | php -- --install-dir=/usr/local/bin --filename=composer \
    && composer --version


RUN groupadd -r appuser && useradd -r -g appuser -d /app appuser
WORKDIR /app

COPY --from=deps /app/node_modules ./node_modules
COPY backend/server.js .
COPY backend/lib ./lib
COPY backend/migrations ./migrations
COPY frontend/public/assets/osa.png ./frontend/public/assets/osa.png

ENV PUPPETEER_SKIP_DOWNLOAD=1
ENV PUPPETEER_EXECUTABLE_PATH=/usr/bin/chromium
ENV NODE_ENV=production
ENV PORT=3001

RUN chown -R appuser:appuser /app
USER appuser
EXPOSE 3001
STOPSIGNAL SIGTERM
CMD ["node", "server.js"]
