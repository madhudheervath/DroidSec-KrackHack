#!/bin/bash

# Start the Backend on an internal fixed port (8000)
# We override the PORTEnv so it doesn't conflict with Next.js
echo "Starting Backend on internal port 8000..."
cd /app/backend
PORT=8000 python3 main.py &
BACKEND_PID=$!

# Wait for backend to be ready (optional but good)
sleep 2

# Start the Frontend on the Railway-assigned port
echo "Starting Frontend on port $PORT..."
cd /app/frontend
npm start

# Cleanup
kill $BACKEND_PID
