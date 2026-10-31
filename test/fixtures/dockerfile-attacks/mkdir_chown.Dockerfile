FROM node:24.22.0-bookworm-slim@sha256:91acba91b842bec0bf7ea6f5e09c644c7ccad72c4996ed9616d861d1c7cd60d4
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts
COPY . .
EXPOSE 3000
RUN mkdir -p /app/data && chown -R node:node /app/data
USER node
CMD ["node", "index.js"]
