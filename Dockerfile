FROM node:24-alpine

WORKDIR /app

COPY package*.json ./
RUN npm ci --omit=dev \
 && rm -rf /usr/local/lib/node_modules/npm /usr/local/bin/npm /usr/local/bin/npx

COPY server.js ./
COPY public ./public
COPY notifications ./notifications

ENV NODE_ENV=production
ENV PORT=3000
ENV DATA_DIR=/app/data

EXPOSE 3000

CMD ["node", "server.js"]
