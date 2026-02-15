#!/bin/bash

# Ensure we have a default port if Railway doesn't provide one (though it should)
APP_PORT="${PORT:-3000}"

# Start the Backend on a fixed internal port
echo "Starting Backend on internal port 8000..."
cd /app/backend
# Specifically bind backend to localhost to keep it internal
PORT=8000 python3 main.py &
BACKEND_PID=$!

# Wait for backend to be ready
echo "Waiting for backend..."
sleep 5

# Start the Frontend on the Railway-assigned port, binding to 0.0.0.0
echo "Starting Frontend on port $APP_PORT (binding to 0.0.0.0)..."
cd /app/frontend
# Explicitly use 0.0.0.0 to ensure Railway's proxy can reach it
HOSTNAME=0.0.0.0 npx next start -p "$APP_PORT"

# Cleanup if frontend exits
kill $BACKEND_PID
