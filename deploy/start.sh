#!/bin/sh
# Container entrypoint: protected API on 127.0.0.1:9000 (never exposed),
# gateway on 0.0.0.0:$PORT.
set -e
PORT="${PORT:-8000}"
export BACKEND_URL="${BACKEND_URL:-http://127.0.0.1:9000}"
export GATEWAY_SELF_URL="${GATEWAY_SELF_URL:-http://127.0.0.1:${PORT}}"

if [ "${RUN_DEMO_API:-true}" = "true" ]; then
  python -m uvicorn demo_api.main:app --host 127.0.0.1 --port 9000 --log-level warning &
  i=0
  until python -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:9000/health',timeout=1)" 2>/dev/null; do
    i=$((i+1)); [ "$i" -gt 40 ] && echo "demo API failed to start" && exit 1; sleep 0.5
  done
fi

exec python -m uvicorn app.main:app --host 0.0.0.0 --port "$PORT" --proxy-headers --forwarded-allow-ips="*" --workers 1
