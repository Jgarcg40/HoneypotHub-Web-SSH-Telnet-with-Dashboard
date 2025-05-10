FROM python:3.10-slim

WORKDIR /app

COPY requirements.txt /app/

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/* \
    && pip install --no-cache-dir -r requirements.txt


RUN groupadd -r appuser -g 1000 && \
    useradd -r -g appuser -u 1000 -d /app appuser

RUN mkdir -p /app/static /app/templates && \
    chmod -R 755 /app && \
    chown -R appuser:appuser /app

COPY . /app/


RUN chown -R appuser:appuser /app

USER appuser


CMD ["python", "/app/src/app.py"] 