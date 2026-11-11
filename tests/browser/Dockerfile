ARG UV_IMAGE
ARG PLAYWRIGHT_IMAGE
FROM ${UV_IMAGE} AS uv
FROM ${PLAYWRIGHT_IMAGE}
COPY --from=uv /uv /usr/local/bin/uv
WORKDIR /work
COPY . /work
ENV PYTHON_DOTENV_DISABLED=1 KESTREL_SKIP_DOTENV=1 KESTREL_PHOENIX_ENABLED=0 KESTREL_TRACING_ENABLED=0 UV_LINK_MODE=copy
RUN uv sync --locked --extra test --python 3.14 && npm ci --prefix web --no-audit --no-fund
CMD ["uv", "run", "--no-sync", "python", "-m", "pytest", "tests/browser", "-q", "-x", "--timeout=60", "--junitxml=/work/native-browser.xml"]
