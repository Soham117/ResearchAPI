# ──────────────────────────────────────────────────────────────
# Dockerfile — FastAPI Rate-Limiter Benchmarking Service
# ──────────────────────────────────────────────────────────────
FROM python:3.12-slim

# Prevent Python from writing .pyc files and enable unbuffered stdout/stderr
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /project

# Install system deps (gcc needed for hiredis C extension, curl for healthcheck)
RUN apt-get update && \
    apt-get install -y --no-install-recommends gcc curl && \
    rm -rf /var/lib/apt/lists/*

# Copy and install Python dependencies first (layer caching)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy entire project source
COPY . .

# Create logs directory
RUN mkdir -p /project/logs

# Expose the FastAPI port
EXPOSE 8000

# Healthcheck for Docker Compose dependency ordering
HEALTHCHECK --interval=5s --timeout=3s --retries=5 \
    CMD curl -f http://localhost:8000/health || exit 1

# Launch uvicorn with 1 worker to prevent concurrent write interleaving on Windows Docker volumes
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
