# Backend image: FastAPI read-API for the mcp-minos frontend.
#
# Note: this image runs the READ-API only. The dynamic scanner's Docker
# sandbox (the `minos dynamic/scan` CLI) needs access to a Docker daemon and is
# not exercised by this container — the UI's live-scan flow is simulated.
FROM python:3.12-slim AS base
WORKDIR /app

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    MINOS_RESULTS_DIR=/app/results \
    MINOS_API_HOST=0.0.0.0 \
    MINOS_API_PORT=8000

# Install the package (pulls FastAPI/uvicorn/etc from pyproject).
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install .

# Configs (tracked). The results/ dir holds runtime scan output and is
# git-ignored, so it isn't part of the build context — create it empty and let
# compose bind-mount real output over it at run time. When empty, the API
# falls back to the bundled sample dataset.
COPY configs ./configs
RUN mkdir -p /app/results

EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=4s --start-period=5s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://localhost:8000/api/health').status==200 else 1)" || exit 1

CMD ["minos-api"]
