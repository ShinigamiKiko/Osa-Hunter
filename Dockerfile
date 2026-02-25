FROM node:20-alpine

RUN apk add --no-cache curl tar && \
    curl -sL "https://github.com/aquasecurity/trivy/releases/download/v0.58.2/trivy_0.58.2_Linux-64bit.tar.gz" \
      | tar -xz -C /usr/local/bin trivy && \
    trivy --version

WORKDIR /app
COPY backend/package.json .
RUN npm install --production
COPY backend/server.js .
COPY frontend/public ./frontend/public

EXPOSE 3001
CMD ["node", "server.js"]
