FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN useradd --create-home --uid 10001 sandboxuser

WORKDIR /app
COPY sandbox_tool.py /app/sandbox_tool.py

RUN mkdir -p /workspace /sandbox && \
    chown -R sandboxuser:sandboxuser /app /workspace /sandbox

USER sandboxuser

ENTRYPOINT ["python", "/app/sandbox_tool.py"]
