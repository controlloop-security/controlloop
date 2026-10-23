# syntax=docker/dockerfile:1.7
#
# The ControlLoop container image: runs `controlloop scan`, `gate`, `diff`,
# `bom`, `init` and `rules` with nothing installed on the host.
#
# Two stages. The builder has uv and installs the locked dependency set
# into a self-contained environment; the runtime stage starts again from
# the bare Python image and copies only that environment in. No uv, no
# compiler, no package manager cache and no source tree reach the image
# that is published. Scanning needs no network, and the image makes no
# network request when it runs (checked in CI by running a scan with
# `--network none`).
#
# Build (from the repository root):
#   docker build -t controlloop --build-arg VERSION=0.2.0 --build-arg REVISION=$(git rev-parse HEAD) .
# Run (mount the repository to scan at /work, read-only):
#   docker run --rm --network none -v "$PWD:/work:ro" controlloop scan /work
#
# The base image is pinned by digest, not by a moving tag, so two builds of
# the same commit start from the same bytes; the runtime stage then applies
# the distribution's security updates, so a fix Debian has shipped since
# the digest was pinned is in the image. `ghcr.io/astral-sh/uv` is pinned
# to the same uv version `.github/workflows/verify.yml` installs.

ARG PYTHON_IMAGE=python:3.12-slim-bookworm@sha256:6a0e06f5ba0b373d051aabd3fffb9b873f27f9a2a3a14bcbe37dee6f0e3bbc70

FROM ghcr.io/astral-sh/uv:0.9.30 AS uv

FROM ${PYTHON_IMAGE} AS builder

COPY --from=uv /uv /usr/local/bin/uv

ENV UV_PROJECT_ENVIRONMENT=/opt/controlloop \
    UV_PYTHON_DOWNLOADS=never \
    UV_LINK_MODE=copy \
    UV_COMPILE_BYTECODE=1

WORKDIR /src
COPY pyproject.toml uv.lock README.md CHANGELOG.md LICENSE NOTICE ./
COPY src ./src

# `--no-dev` leaves out the test and release tooling groups; `--no-editable`
# installs the package itself into the environment so the source tree is
# not needed at run time. `--locked` refuses to run if `uv.lock` is stale.
RUN uv sync --locked --no-dev --no-editable --python /usr/local/bin/python3

FROM ${PYTHON_IMAGE} AS runtime

ARG VERSION=unknown
ARG REVISION=unknown

LABEL org.opencontainers.image.title="ControlLoop" \
      org.opencontainers.image.description="Local-first security scanner and deterministic CI gate for AI agents" \
      org.opencontainers.image.url="https://controlloop.ai" \
      org.opencontainers.image.source="https://github.com/controlloop-security/controlloop" \
      org.opencontainers.image.documentation="https://github.com/controlloop-security/controlloop/blob/main/docs/reference/container-image.md" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.vendor="ControlLoop" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}"

# `diff`, `scan` and `gate` resolve the merge-base baseline through local
# git plumbing, so git is the one system package added. It is a runtime
# tool, not a build toolchain, and it is installed without recommends.
# The Python base image ships pip, setuptools and wheel; none is needed to
# run the installed package, and a runtime image carries no installer.
RUN apt-get update \
    && apt-get upgrade -y --no-install-recommends \
    && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/* \
    && python3 -m pip uninstall --yes pip setuptools wheel \
    && rm -rf /usr/local/lib/python3.12/ensurepip /root/.cache \
    && groupadd --gid 10001 controlloop \
    && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin controlloop \
    && mkdir /work && chown 10001:10001 /work

COPY --from=builder /opt/controlloop /opt/controlloop

ENV PATH=/opt/controlloop/bin:${PATH} \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HOME=/tmp

# A mounted repository is owned by someone else as far as git is concerned;
# without this, git refuses to read it ("dubious ownership") and the
# merge-base baseline silently becomes unavailable.
ENV GIT_CONFIG_COUNT=1 \
    GIT_CONFIG_KEY_0=safe.directory \
    GIT_CONFIG_VALUE_0=*

WORKDIR /work
USER 10001:10001

ENTRYPOINT ["controlloop"]
CMD ["--help"]
