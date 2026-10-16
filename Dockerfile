FROM node:24-alpine AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY tsconfig.json tsconfig.build.json ./
COPY src ./src
COPY scripts ./scripts
RUN npm run build && npm prune --omit=dev

FROM node:24-alpine
ENV NODE_ENV=production
WORKDIR /app
COPY --from=build --chown=node:node /app/node_modules ./node_modules
COPY --from=build --chown=node:node /app/dist ./dist
COPY --from=build --chown=node:node /app/scripts ./scripts
COPY --chown=node:node package.json ./
USER node
EXPOSE 9000
HEALTHCHECK --interval=15s --timeout=3s --start-period=20s --retries=3 CMD ["node", "-e", "fetch(`http://127.0.0.1:${process.env.PORT || 9000}/healthz`).then((response) => process.exit(response.ok ? 0 : 1)).catch(() => process.exit(1))"]
CMD ["node", "dist/server.js"]