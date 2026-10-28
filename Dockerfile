# Single-container image: runs the protected demo API (internal, port 9000)
# and the API Fortress gateway (public, $PORT). Suitable for Render, Railway,
# Fly.io or any VPS. For a split deployment use docker-compose.yml.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PORT=8000

WORKDIR /app
RUN useradd --create-home --uid 10001 fortress
COPY requirements.txt requirements-prod.txt ./
RUN pip install -r requirements-prod.txt

COPY app ./app
COPY demo_api ./demo_api
COPY dashboard ./dashboard
COPY scripts ./scripts
COPY data/sample_logs ./data/sample_logs
COPY deploy/start.sh ./start.sh
RUN chmod +x start.sh && mkdir -p /app/data && chown -R fortress:fortress /app

USER fortress
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=4s --start-period=20s CMD python -c "import os,urllib.request;urllib.request.urlopen(f'http://127.0.0.1:{os.environ.get(\"PORT\",\"8000\")}/gateway/health',timeout=3)"
CMD ["./start.sh"]
