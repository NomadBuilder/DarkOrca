#!/bin/bash
# Start SecurityScan Web UI

cd "$(dirname "$0")"

# Set PATH for tools
export PATH=$PATH:$(go env GOPATH)/bin:/opt/homebrew/bin

echo "🚀 Starting SecurityScan Web UI..."
echo ""
echo "📍 Web interface will be available at: http://localhost:8080"
echo "📖 Open your browser and navigate to the URL above"
echo ""
echo "Press Ctrl+C to stop the server"
echo ""

python3 web_app.py

