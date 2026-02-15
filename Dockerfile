# Build Stage for Frontend
FROM node:18-slim AS frontend-builder
WORKDIR /app/frontend
COPY frontend/package*.json ./
# Reduce memory usage and prevent timeouts
RUN npm install --no-audit --no-fund
COPY frontend/ ./
RUN npm run build

# Final Stage - Start from Node slim to ensure stable frontend runtime
FROM node:18-slim

# Install Python, Java 17, and utilities in a more robust way
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    openjdk-17-jre-headless \
    curl \
    unzip \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy Backend and install requirements
# Using pip3 specifically for the debian environment
COPY backend/ /app/backend/
RUN pip3 install --no-cache-dir --break-system-packages -r /app/backend/requirements.txt

# Setup Analysis Tools (apktool, jadx)
COPY setup_tools.sh /app/setup_tools.sh
RUN chmod +x /app/setup_tools.sh && ./app/setup_tools.sh

# Copy Built Frontend from builder
COPY --from=frontend-builder /app/frontend/.next /app/frontend/.next
COPY --from=frontend-builder /app/frontend/public /app/frontend/public
COPY --from=frontend-builder /app/frontend/package*.json /app/frontend/
COPY --from=frontend-builder /app/frontend/next.config.mjs /app/frontend/

# Install only production dependencies for frontend
WORKDIR /app/frontend
RUN npm install --omit=dev --no-audit --no-fund

WORKDIR /app

# Create necessary architecture directories
RUN mkdir -p /app/backend/uploads /app/backend/reports

# Copy Startup script
COPY start.sh /app/start.sh
RUN chmod +x /app/start.sh

# Railway uses the PORT env var
ENV PORT 3000
EXPOSE 3000

# Run the unified startup script
CMD ["/app/start.sh"]
