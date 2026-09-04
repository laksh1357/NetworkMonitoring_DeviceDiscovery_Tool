FROM python:3.11-slim

# Install network utilities and system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    iputils-ping \
    net-tools \
    arp-scan \
    procps \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY . .

EXPOSE 8000

# Run NOC Web Server
CMD ["python", "web_server.py"]
