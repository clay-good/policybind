# PolicyBind Docker Image
#
# Multi-stage build for a minimal, secure production image.
#
# Build:
#   docker build -t policybind .
#
# Run server:
#   docker run -p 8080:8080 -v /path/to/policies:/app/policies policybind
#
# Run CLI:
#   docker run --rm policybind policybind --help

# =============================================================================
# Stage 1: Builder
# =============================================================================
FROM python:3.11-slim AS builder

WORKDIR /build

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy only what's needed for installation
COPY pyproject.toml README.md ./
COPY policybind/ ./policybind/

# Create virtual environment and install package
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Install with server extras for full functionality
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir ".[server]"

# =============================================================================
# Stage 2: Production Image
# =============================================================================
FROM python:3.11-slim AS production

# Security: Run as non-root user
RUN groupadd --gid 1000 policybind && \
    useradd --uid 1000 --gid 1000 --shell /bin/bash --create-home policybind

WORKDIR /app

# Copy virtual environment from builder
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy application code
COPY --chown=policybind:policybind policybind/ ./policybind/
COPY --chown=policybind:policybind configs/ ./configs/
COPY --chown=policybind:policybind examples/ ./examples/

# Create directories for runtime data
RUN mkdir -p /app/data /app/policies /app/logs && \
    chown -R policybind:policybind /app

# Environment configuration
ENV POLICYBIND_DATABASE_PATH=/app/data/policybind.db \
    POLICYBIND_LOG_LEVEL=INFO \
    POLICYBIND_LOG_FORMAT=json \
    POLICYBIND_SERVER_HOST=0.0.0.0 \
    POLICYBIND_SERVER_PORT=8080

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/v1/health')" || exit 1

# Switch to non-root user
USER policybind

# Expose API port
EXPOSE 8080

# Default command: run the server
CMD ["python", "-m", "policybind.server", "--host", "0.0.0.0", "--port", "8080"]

# =============================================================================
# Stage 3: Development Image
# =============================================================================
FROM production AS development

USER root

# Install development dependencies
RUN pip install --no-cache-dir pytest pytest-cov pytest-asyncio mypy ruff

# Copy test files
COPY --chown=policybind:policybind tests/ ./tests/

USER policybind

# Default command for development: run tests
CMD ["pytest", "-v"]
