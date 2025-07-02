FROM node:18-alpine

WORKDIR /app

# Copy package.json
COPY package.json ./

# Install dependencies using npm install (not npm ci)
RUN npm install --only=production

# Copy application code
COPY . .

# Expose port
EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD curl --fail http://localhost:3000 || exit 1


# Start the application
CMD ["node", "server.js"]
