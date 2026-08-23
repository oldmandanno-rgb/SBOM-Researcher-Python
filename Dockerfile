# syntax=docker/dockerfile:1
# =============================================================================
# osv-service container image
# Base: Chainguard python (Wolfi) — minimal, low-CVE, distroless runtime.
#
# Pinned by @sha256 digest (per AGENTS.md "Hash-Pinned Requirements" so the
# OpenSSF Scorecard Pinned-Dependencies check passes).
#
# NOTE on tags: Chainguard's FREE "Starter" python image only publishes the
# `latest` / `latest-dev` tags. Version-pinned tags (e.g. 3.12) require a paid
# plan, so we pin the DIGEST of `latest` / `latest-dev` instead of a version
# tag. Regenerate these digests with:  scripts/fetch-digest.sh
# =============================================================================
ARG CHAINGUARD_DIGEST_DEV=sha256:04b9b391d20755510e951ae20950af5af3a917ee9a197a9539000533d5c6b713
ARG CHAINGUARD_DIGEST_RUNTIME=sha256:1878eed1c7e2731f1b52a5a7f4821f413581fcaf034ea7352bc8898243a1bdce

# ---------------------------------------------------------------------------
# Builder: full Python + pip + shell (latest-dev) to install deps.
# ---------------------------------------------------------------------------
FROM cgr.dev/chainguard/python:latest-dev@${CHAINGUARD_DIGEST_DEV} AS builder

# Chainguard images run as nonroot by default; switch to root for the build
# stage (it is discarded) so we can create the venv at /venv and install deps.
USER root

ENV LANG=C.UTF-8 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /build

# Build the virtualenv at /venv (NOT /build/venv) so the script shebangs
# (#!/venv/bin/python) remain valid after we COPY it into the runtime image.
RUN python -m venv /venv
ENV PATH="/venv/bin:$PATH"

# Hash-pinned dependency lock (generated on Linux — see requirements-osv-service.in).
# Pure-Python wheels only; no system libs needed (downloader uses HTTPS, not git).
COPY requirements-osv-service.txt /venv/
RUN pip install --no-cache-dir --require-hashes -r /venv/requirements-osv-service.txt

# Install THIS project (--no-deps: runtime deps come from the lockfile above).
# --require-hashes + --no-build-isolation: deps are already hash-pinned in the
# venv; disabling build isolation satisfies the Scorecard Pinned-Dependencies
# pip check without pulling unpinned build deps from PyPI.
COPY pyproject.toml /build/
COPY src /build/src
RUN pip install --no-cache-dir --no-deps --no-build-isolation --require-hashes /build

# Writable data dir for the OSV store, owned by the runtime's nonroot user (65532).
RUN mkdir -p /data && chown -R 65532:65532 /data

# ---------------------------------------------------------------------------
# Runtime: distroless minimal Python (latest) — no shell, no package manager.
# Avoid RUN here (no shell); only COPY/ENV/EXPOSE/ENTRYPOINT/USER.
# ---------------------------------------------------------------------------
FROM cgr.dev/chainguard/python:latest@${CHAINGUARD_DIGEST_RUNTIME}

ENV LANG=C.UTF-8 \
    PYTHONUNBUFFERED=1 \
    OSV_DATA_DIR=/data \
    PATH="/venv/bin:$PATH"

WORKDIR /app

# Virtualenv (includes osv_service + sbom_researcher packages and the
# `osv-service` console script). Path matches the builder (/venv).
COPY --from=builder /venv /venv
COPY --from=builder /data /data

# Runs as the image's built-in nonroot user (Chainguard default).
USER nonroot:nonroot

EXPOSE 8000

# `osv-service serve` -> uvicorn.run(create_app()) from src/osv_service/cli.py
ENTRYPOINT ["osv-service", "serve", "--host", "0.0.0.0", "--port", "8000", "--data-dir", "/data"]
