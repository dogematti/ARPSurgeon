# ARPSurgeon Dockerfile
# Base image
FROM python:3.11-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DEBIAN_FRONTEND=noninteractive

# Install system dependencies
# libpcap-dev: required for scapy
# tcpdump, net-tools, iproute2: useful for debugging inside container
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap-dev \
    tcpdump \
    net-tools \
    iproute2 \
    procps \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy project files
COPY . .

# Create directory for artifacts/captures
RUN mkdir -p artifacts

# Expose Web API port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD curl -f http://localhost:8000/api/v1/stats || exit 1

# Entrypoint
# Default command starts the web interface, but can be overridden
ENTRYPOINT ["python", "-m", "arpsurgeon"]
CMD ["web", "--host", "0.0.0.0", "--port", "8000"]
