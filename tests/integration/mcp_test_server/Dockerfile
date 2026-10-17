FROM python:3.11-slim

WORKDIR /app

# Match the native protocol SDK used by the host.
RUN pip install "mcp>=2.3,<3"

# Copy server code
COPY server.py .

# Expose port
EXPOSE 8000

# Run server
CMD ["python", "server.py"]
