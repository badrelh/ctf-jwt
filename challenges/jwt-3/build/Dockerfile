FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install curl for health check
RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY app.py .
COPY templates/ templates/
COPY static/ static/

# Create non-root user for security
RUN useradd -m -u 1000 ctfuser && \
    chown -R ctfuser:ctfuser /app

USER ctfuser

# Expose port (default 5000, can be overridden)
EXPOSE 5000

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:${PORT:-5000}/health || exit 1

# Run the application
CMD ["python", "app.py"]
