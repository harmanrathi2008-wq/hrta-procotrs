FROM python:3.11-slim

# Install system dependencies required for OpenCV and MediaPipe
RUN apt-get update && apt-get install -y --no-install-recommends \
    libgl1 \
    libglib2.0-0 \
    libgomp1 \
    libsm6 \
    libxext6 \
    libxrender1 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Upgrade build tools to support pre-compiled wheels
RUN pip install --no-cache-dir --upgrade pip setuptools wheel

# Copy dependency definition
COPY requirements.txt .

# Install dependencies (no-cache to keep image small)
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source code
COPY . .

# Expose port (default 8000 or Render PORT)
EXPOSE 8000

# Start FastAPI via Uvicorn respecting $PORT
CMD ["sh", "-c", "exec uvicorn main:app --host 0.0.0.0 --port ${PORT:-8000}"]
