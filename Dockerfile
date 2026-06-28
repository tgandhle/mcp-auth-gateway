# syntax=docker/dockerfile:1

# ---- Stage 1: build a self-contained virtualenv from the locked deps --------
# We install from uv.lock (not pyproject ranges) so the image is reproducible:
# the same lock that CI verifies is what ships.
FROM python:3.12-slim AS builder

# uv: pinned by digest-free version tag; the binary is copied from the official
# distroless image so we don't curl an installer at build time.
COPY --from=ghcr.io/astral-sh/uv:0.11 /uv /uvx /usr/local/bin/

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PROJECT_ENVIRONMENT=/opt/venv

WORKDIR /app

# Install deps first (cached layer) using only the lock + manifest, before the
# source is copied, so code changes don't bust the dependency layer.
COPY pyproject.toml uv.lock ./
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-install-project --no-dev

# Now copy the source and install the project itself into the same venv.
COPY src ./src
COPY examples ./examples
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev

# ---- Stage 2: minimal runtime, non-root ------------------------------------
FROM python:3.12-slim AS runtime

# Create an unprivileged user. Running as non-root is a baseline container
# hardening control: a compromised process cannot trivially write the image
# or escalate via root-owned paths.
RUN groupadd --system --gid 10001 app \
    && useradd --system --uid 10001 --gid app --no-create-home --home-dir /app app

# Copy the prebuilt venv and source from the builder. Nothing in the runtime
# image needs uv, a compiler, or the lockfile.
COPY --from=builder --chown=app:app /opt/venv /opt/venv
COPY --from=builder --chown=app:app /app/src /app/src
COPY --from=builder --chown=app:app /app/examples /app/examples

ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    # Bind to all interfaces inside the container; the pod/network boundary,
    # not the bind address, is what restricts who can reach it.
    GATEWAY_HOST=0.0.0.0 \
    GATEWAY_PORT=8080

WORKDIR /app
USER app

EXPOSE 8080

# Liveness via the app's own public health endpoint. Uses python (already
# present) rather than adding curl to the image.
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/healthz').status==200 else 1)"

ENTRYPOINT ["python", "-m", "mcp_gateway"]
