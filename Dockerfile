FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update &&     apt-get install -y --no-install-recommends     openssh-client     iputils-ping     dnsutils     && rm -rf /var/lib/apt/lists/*

# Copy requirements
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the CDP crawler script
COPY cdp_crawler.py .

# Create output directory
RUN mkdir -p /output

# Set environment variables
ENV PYTHONUNBUFFERED=1

# Make script executable
RUN chmod +x cdp_crawler.py

# Default command
ENTRYPOINT [python3, cdp_crawler.py]
