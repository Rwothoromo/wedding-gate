FROM node:20-alpine
WORKDIR /app

# Install only production deps first (better layer caching)
COPY package*.json ./
RUN npm install --omit=dev

# App source (card-generator is excluded via .dockerignore)
COPY . .

EXPOSE 3000
CMD ["node", "server.js"]
