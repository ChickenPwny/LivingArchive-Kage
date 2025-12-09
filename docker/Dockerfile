FROM python:3.13-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    nmap \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Copy all source code
COPY daemons/ /app/daemons/
COPY kage/ /app/kage/
COPY kumo/ /app/kumo/
COPY ryu/ /app/ryu/
COPY *.py /app/
COPY __init__.py /app/

# Add project root to Python path
ENV PYTHONPATH=/app

# Set default command (can be overridden in docker-compose)
CMD ["python3", "/app/daemons/kage_daemon.py"]

