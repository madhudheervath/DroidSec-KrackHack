#!/bin/bash

# Ensure we have a default port if Railway doesn't provide one
APP_PORT="${PORT:-3000}"

# Start the Backend on a fixed internal localhost port
echo "Starting Backend on internal 127.0.0.1:8000..."
cd /app/backend
# Override main.py by passing host as argument if possible, or trust env logic
# Here we force main.py logic to bind to 127.0.0.1 by wrapping it or modifying it
# Actually, I will modify main.py as well to be safe.
PORT=8000 python3 main.py &
BACKEND_PID=$!

# Wait for backend to be ready
echo "Waiting for backend..."
sleep 5

# Start the Frontend on the Railway-assigned port, binding to 0.0.0.0
echo "Starting Frontend on port $APP_PORT (binding to 0.0.0.0)..."
cd /app/frontend
# Use -H 0.0.0.0 to be absolutely sure it's public
npx next start -H 0.0.0.0 -p "$APP_PORT"

# Cleanup if frontend exits
kill $BACKEND_PID
