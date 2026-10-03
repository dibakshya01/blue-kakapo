# blue-kakapo control-plane image.
# Multi-stage: resolve deps with uv, then run a slim runtime. Built for localhost and K8s alike.
FROM python:3.12-slim AS base

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    UV_LINK_MODE=copy \
    UV_COMPILE_BYTECODE=1

# uv for fast, reproducible installs.
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

WORKDIR /app

# Install dependencies first (layer-cached), then the project.
COPY pyproject.toml README.md ./
COPY src ./src
COPY web/dist ./web/dist
RUN uv sync --no-dev --extra postgres --extra otel

# Non-root runtime user.
RUN useradd --create-home --uid 10001 kakapo && chown -R kakapo:kakapo /app
USER kakapo

ENV PATH="/app/.venv/bin:${PATH}" \
    BK_API_HOST=0.0.0.0 \
    BK_API_PORT=8713

EXPOSE 8713

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8713/healthz').status==200 else 1)"

CMD ["bk", "serve"]
