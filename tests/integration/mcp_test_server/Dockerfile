FROM python:3.11-slim

WORKDIR /app

# Install dependencies.
#
# The mcp bound must match the package's own (see pyproject.toml): this image
# is built fresh at test time, so an unbounded spec silently tracks whatever is
# newest on PyPI rather than what the code under test supports. mcp 2.0 removed
# `mcp.server.fastmcp`, which server.py imports, so the container started
# exiting at import the day 2.0 shipped — turning a dependency problem into a
# "container exited unexpectedly" failure several layers from its cause.
RUN pip install "mcp[cli]>=1.26,<2" uvicorn starlette

# Copy server code
COPY server.py .

# Expose port
EXPOSE 8000

# Run server
CMD ["python", "server.py"]
