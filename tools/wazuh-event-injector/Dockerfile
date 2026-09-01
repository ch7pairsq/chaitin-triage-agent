FROM node:22.23.2-alpine3.24

WORKDIR /app
COPY package.json ./
COPY src ./src

USER node
CMD ["node", "src/index.js"]
