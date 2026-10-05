FROM node:24-alpine
WORKDIR /app
ENV NODE_ENV=production KPS_DATA_DIR=/data KPS_PORT=8787
COPY package.json package-lock.json ./
RUN npm ci --omit=dev && npm cache clean --force
COPY src ./src
COPY public ./public
RUN mkdir -p /data && chown node:node /data
USER node
VOLUME /data
EXPOSE 8787
HEALTHCHECK --interval=30s --timeout=5s CMD wget -qO- http://127.0.0.1:8787/api/v1/status >/dev/null || exit 1
CMD ["node", "--disable-warning=ExperimentalWarning", "src/main.ts", "serve"]
