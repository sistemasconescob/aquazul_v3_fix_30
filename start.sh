#!/bin/bash
cd "$(dirname "$0")"
[ -f .env ] && export $(grep -v '^#' .env | grep -v '^$' | xargs)
echo "🌊 Aquazul → http://localhost:${PORT:-8000}"
cd backend && python3 server.py
