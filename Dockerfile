FROM node:16-alpine

WORKDIR /app

# Install curl
RUN apk add --no-cache curl

COPY package*.json ./
RUN npm install --production

COPY . .

EXPOSE 3000

# Add healthcheck
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD curl --fail http://localhost:3000 || exit 1

CMD ["npm", "start"]
