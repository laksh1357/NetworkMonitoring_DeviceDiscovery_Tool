FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    API_HOST=0.0.0.0 \
    API_PORT=8000 \
    DATABASE_PATH=/data/network_logs.db \
    WEB_CONCURRENCY=1

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
RUN mkdir -p /data

EXPOSE 8000

# The API process is intentionally single-process. Monitoring workers are not
# started by this deployment entry point, preventing duplicate schedulers.
CMD ["python", "-m", "src.api.server"]
