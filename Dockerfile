# Base sandbox image for snitch-test
# This image provides the foundation for dependency scanning sandboxes.
# Project-specific Dockerfiles are generated dynamically by snitch-test.

FROM python:3.12-slim

# Install network monitoring tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    tcpdump \
    net-tools \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user for sandbox
RUN useradd -m -s /bin/bash sandbox

WORKDIR /app

# Default entrypoint runs the capture script
ENTRYPOINT ["python3", "/capture.py"]
