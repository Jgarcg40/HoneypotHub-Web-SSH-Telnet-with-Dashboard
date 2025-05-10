FROM python:3.10-slim

WORKDIR /app

COPY requirements.txt /app/

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/* \
    && pip install --no-cache-dir -r requirements.txt

RUN groupadd -r appuser -g 1000 && \
    useradd -r -g appuser -u 1000 -d /app appuser

RUN mkdir -p /app/logs && \
    touch /app/logs/honeypot.log && \
    chmod -R 755 /app && \
    chmod -R 750 /app/logs && \
    chown -R appuser:appuser /app

COPY . /app/


RUN chown -R appuser:appuser /app


EXPOSE 5000


USER appuser


CMD ["python", "/app/src/main.py"] 