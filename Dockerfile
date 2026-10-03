FROM python:3.12-slim
COPY --from=ghcr.io/astral-sh/uv:0.12.5 /uv /uvx /bin/

WORKDIR /app

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    MIJIA_DATA_DIR=/data \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never

COPY pyproject.toml uv.lock .
RUN uv sync --locked --no-dev --no-install-project && uv pip check

COPY src/ ./src/
ENV PATH="/app/.venv/bin:$PATH"

EXPOSE 8080
CMD ["python", "src/server.py"]
