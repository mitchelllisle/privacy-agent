FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

COPY pyproject.toml ./
RUN pip install --no-cache-dir uv \
    && uv sync --no-dev

COPY src ./src
COPY baml_src ./baml_src

ENV PYTHONPATH=/app/src
ENV PORT=8080

EXPOSE 8080

CMD ["uv", "run", "python", "-m", "privacyagent.__main__"]
