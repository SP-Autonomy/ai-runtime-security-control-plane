# =============================================================================
# AIRS-CP Gateway Dockerfile
# AI Runtime Security Control Plane - Phase 1
# =============================================================================

FROM python:3.11-slim

# Metadata
LABEL maintainer="AIRS-CP"
LABEL description="AI Runtime Security Control Plane Gateway"
LABEL version="0.1.0"

# Environment
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user for security
RUN useradd --create-home --shell /bin/bash airs

# Set working directory
WORKDIR /app

# Copy dependency files first (better layer caching)
COPY pyproject.toml ./

# Install Python dependencies
RUN pip install --upgrade pip && \
    pip install .

# Copy source code
COPY src/ ./src/

# Install the package
RUN pip install -e .

# Create data directory
RUN mkdir -p /data && chown -R airs:airs /data

# Switch to non-root user
USER airs

# Expose port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Run the gateway
CMD ["python", "-m", "uvicorn", "airs_cp.gateway.app:app", "--host", "0.0.0.0", "--port", "8080"]
