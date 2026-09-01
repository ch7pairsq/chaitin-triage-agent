FROM node:22.23.2-alpine3.24

RUN apk add --no-cache git docker-cli docker-cli-compose
WORKDIR /app
COPY package.json ./
COPY src ./src
USER node
CMD ["node", "src/server.js"]
