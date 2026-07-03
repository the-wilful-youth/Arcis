# Use a lightweight official Python runtime
FROM python:3.13-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PORT=5001

# Set the working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    dnsutils \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application code
COPY . .

# Expose the API port
EXPOSE 5001

# Run the application using gunicorn for production orchestration
CMD ["gunicorn", "-w", "2", "-b", "0.0.0.0:5001", "--chdir", "backend", "app:app"]
