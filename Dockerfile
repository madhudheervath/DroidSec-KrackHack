# Build Stage for Frontend
FROM node:18-slim AS frontend-builder
WORKDIR /app/frontend
COPY frontend/package*.json ./
RUN npm install
COPY frontend/ ./
# We need to set this if we use absolute URLs, but since we fixed api.ts to be relative, we are fine.
RUN npm run build

# Final Stage
FROM python:3.10-slim

# Install system dependencies (Java 17, Node.js for Next.js runtime, and utilities)
RUN apt-get update && apt-get install -y \
    openjdk-17-jre-headless \
    curl \
    && curl -fsSL https://deb.nodesource.com/setup_18.x | bash - \
    && apt-get install -y nodejs \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy Backend
COPY backend/ /app/backend/
RUN pip install --no-cache-dir -r /app/backend/requirements.txt

# Copy Tools
COPY tools/ /app/tools/
RUN chmod +x /app/tools/apktool /app/tools/jadx/bin/jadx

# Copy Built Frontend
COPY --from=frontend-builder /app/frontend/.next /app/frontend/.next
COPY --from=frontend-builder /app/frontend/public /app/frontend/public
COPY --from=frontend-builder /app/frontend/package*.json /app/frontend/
COPY --from=frontend-builder /app/frontend/next.config.mjs /app/frontend/

# Install only production dependencies for frontend
WORKDIR /app/frontend
RUN npm install --omit=dev

WORKDIR /app

# Create necessary directories
RUN mkdir -p /app/backend/uploads /app/backend/reports

# Startup script to run both processes
COPY start.sh /app/start.sh
RUN chmod +x /app/start.sh

# Railway uses the PORT env var
ENV PORT 3000
EXPOSE 3000

CMD ["/app/start.sh"]
