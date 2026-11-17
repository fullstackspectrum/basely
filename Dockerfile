# syntax=docker/dockerfile:1

# Docker Hardened Images (https://dhi.io), Alpine variant: a minimal, non-root Python
# runtime with no shell or package manager. Pulling them needs `docker login dhi.io`
# with a Docker account. Python 3.14 reads zstd-compressed layers natively.
ARG PYTHON_VERSION=3.14

FROM dhi.io/python:${PYTHON_VERSION}-alpine-dev AS build
WORKDIR /src
COPY pyproject.toml README.md LICENSE ./
COPY basely ./basely
# The venv is created without pip so the runtime image ships only Basely (which has
# no runtime dependencies); the build stage's pip installs into it from outside.
RUN python3 -m venv --without-pip /opt/venv \
    && pip --python /opt/venv/bin/python install --no-cache-dir . \
    && mkdir /data

FROM dhi.io/python:${PYTHON_VERSION}-alpine
ARG VERSION=dev
LABEL org.opencontainers.image.title="basely" \
      org.opencontainers.image.description="Compare container base images on vulnerabilities, size and fit, and pick a better one" \
      org.opencontainers.image.source="https://github.com/fullstackspectrum/basely" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.version="${VERSION}"

# Mount ~/.docker at /docker to use registry logins stored inline in config.json.
# The cache goes to /tmp, which the non-root user can always write.
ENV PATH=/opt/venv/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DOCKER_CONFIG=/docker \
    BASELY_CACHE_DIR=/tmp/basely

COPY --from=build /opt/venv /opt/venv
# The runtime image has no shell, so /data is created in the build stage.
COPY --from=build --chown=65532:65532 /data /data

# The base image already runs as the non-root user 65532; this makes it explicit.
USER 65532:65532
# Mount the directory holding the Dockerfile here; reports are written relative to it.
WORKDIR /data
ENTRYPOINT ["basely"]
CMD ["--help"]
