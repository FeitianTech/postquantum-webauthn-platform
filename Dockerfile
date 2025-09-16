# Use Python 3.12 slim image
FROM python:3.12-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the application code
COPY . .

# Set environment variables
ENV FLASK_APP=examples/server/server/server.py
ENV FLASK_ENV=production
ENV PORT=8080

# Create directory for credential storage
RUN mkdir -p /app/credentials

# Expose port
EXPOSE 8080

# Run the application
CMD ["python", "-m", "flask", "run", "--host=0.0.0.0", "--port=8080"]