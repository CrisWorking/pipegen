FROM node:24.22.0-bookworm-slim@sha256:91acba91b842bec0bf7ea6f5e09c644c7ccad72c4996ed9616d861d1c7cd60d4 AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts --git=/usr/bin/git
COPY . .
RUN npm run build
FROM build
EXPOSE 3000
USER node
CMD ["node", "dist/index.js"]
