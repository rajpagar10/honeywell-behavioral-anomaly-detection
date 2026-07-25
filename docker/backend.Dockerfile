FROM python:3.11-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

RUN groupadd --system badp \
    && useradd --system --gid badp --home-dir /app badp

COPY pyproject.toml README.md ./
COPY backend ./backend
RUN python -m pip install --no-cache-dir .

COPY config ./config
RUN mkdir -p /var/lib/badp/runtime /var/lib/badp/evaluation \
    && chown -R badp:badp /app /var/lib/badp

USER badp

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/ready', timeout=3)"]

CMD ["badp", "--config", "config/base.yaml", "serve"]
