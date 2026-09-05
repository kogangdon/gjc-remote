# syntax=docker/dockerfile:1.7

ARG BUN_IMAGE=oven/bun:1.3.14@sha256:e10577f0db68676a7024391c6e5cb4b879ebd17188ab750cf10024a6d700e5c4
ARG LOCK_SHA256=bf725eeda5335a4df681662ed916ba675448fd6f43d153bc41e22e5e81642bd5

FROM ${BUN_IMAGE} AS deps
ARG LOCK_SHA256
WORKDIR /app
COPY package.json bun.lock ./
COPY bot/package.json ./bot/package.json
COPY daemon/package.json ./daemon/package.json
COPY native-control/package.json ./native-control/package.json
COPY shared/package.json ./shared/package.json
RUN echo "${LOCK_SHA256}  bun.lock" | sha256sum --check --strict \
    && bun install --frozen-lockfile --production --ignore-scripts \
      --filter @gjc-remote/daemon \
    && bun -e 'const p=require("./node_modules/@gajae-code/coding-agent/package.json"); if(p.version!=="0.12.21") process.exit(1)'

# Test-only registration peer. This stage intentionally precedes the signed
# native bundle stage so Compose validation can build it without release keys.
FROM ${BUN_IMAGE} AS fixture-relay
USER root
RUN groupadd --gid 1004 gjc \
    && useradd --uid 1004 --gid 1004 --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin gjc
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY shared ./shared
COPY deploy/docker/daemon/fixture-relay.js ./fixture-relay.js
USER 1004:1004
ENTRYPOINT ["bun", "/app/fixture-relay.js"]

FROM ${BUN_IMAGE} AS runtime-base
USER root
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
      ca-certificates=20250419 \
      git=1:2.47.3-0+deb13u1 \
      libacl1=2.3.2-2+b1 \
      tini=0.19.0-3+b7 \
    && groupadd --gid 1004 gjc \
    && useradd --uid 1004 --gid 1004 --create-home --home-dir /home/gjc --shell /usr/sbin/nologin gjc \
    && mkdir -p /workspaces /var/lib/gjc-remote/sessions /var/lib/gjc-remote/state /home/gjc/.gjc \
    && chown -R 1004:1004 /workspaces /var/lib/gjc-remote /home/gjc \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY daemon/package.json ./daemon/package.json
COPY daemon/src ./daemon/src
COPY native-control/package.json ./native-control/package.json
COPY native-control/src ./native-control/src
COPY native-control/scripts ./native-control/scripts
COPY native-control/release-keys/trusted.json ./native-control/release-keys/trusted.json
COPY shared ./shared
COPY deploy/docker/daemon/preflight-probe.js ./preflight-probe.js
COPY deploy/docker/daemon/persistence-probe.js ./persistence-probe.js

# Test-only stage used by Linux CI to execute the real procfs/cgroup/mount
# preflight without manufacturing an unsigned daemon runtime image.
FROM runtime-base AS preflight-probe
USER 1004:1004
ENTRYPOINT ["bun", "/app/preflight-probe.js"]

# CI-only daemon for exercising the disposable Compose topology. It is
# intentionally not the signed `runtime` target and keeps inventory/serving
# disabled, so it cannot produce positive workspace-serving evidence.
FROM runtime-base AS compose-fixture-daemon
LABEL io.gjc-remote.test-only="true"
ENV NODE_ENV=production \
    HOME=/home/gjc \
    GJC_CONTAINER_RUNTIME=1 \
    GJC_DAEMON_SESSION_ROOT=/var/lib/gjc-remote/sessions \
    GJC_DAEMON_STATE_ROOT=/var/lib/gjc-remote/state \
    GJC_NATIVE_WORKSPACE_ROOT=/workspaces \
    GJC_NATIVE_INVENTORY_MODE=off \
    GJC_NATIVE_WORKSPACE_SERVING=0 \
    GJC_READINESS_V2=1 \
    GJC_SHUTDOWN_TIMEOUT_MS=15000
USER 1004:1004
ENTRYPOINT ["/usr/bin/tini", "--", "bun", "/app/daemon/src/container-entrypoint.js"]

# Release/runtime builds MUST provide this named BuildKit context. Its root
# contains the externally signed, platform-matched native-control artifacts.
FROM native_control_bundle AS signed-native

FROM runtime-base AS runtime
ARG VERSION=0.3.1
ARG REVISION
ARG LOCK_SHA256
RUN test -n "${REVISION}" && test "${REVISION}" != unknown
LABEL org.opencontainers.image.title="gjc-remote daemon" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.source="https://github.com/kogangdon/gjc-remote" \
      org.opencontainers.image.base.name="oven/bun:1.3.14@sha256:e10577f0db68676a7024391c6e5cb4b879ebd17188ab750cf10024a6d700e5c4" \
      io.gjc-remote.lock.sha256="${LOCK_SHA256}" \
      io.gjc-remote.sdk.version="0.12.21"

COPY --chmod=0444 --from=signed-native /native_control.node ./native-control/build/Release/native_control.node
COPY --chmod=0444 --from=signed-native /native-control.manifest.json ./native-control/build/Release/native-control.manifest.json
COPY --chmod=0444 --from=signed-native /native-control.manifest.json.sig ./native-control/build/Release/native-control.manifest.json.sig
RUN chmod 0555 ./native-control/build ./native-control/build/Release \
    && bun native-control/scripts/verify-build.mjs --require-signature

ENV NODE_ENV=production \
    HOME=/home/gjc \
    GJC_CONTAINER_RUNTIME=1 \
    GJC_DAEMON_SESSION_ROOT=/var/lib/gjc-remote/sessions \
    GJC_DAEMON_STATE_ROOT=/var/lib/gjc-remote/state \
    GJC_NATIVE_WORKSPACE_ROOT=/workspaces \
    GJC_NATIVE_INVENTORY_MODE=off \
    GJC_NATIVE_WORKSPACE_SERVING=0 \
    GJC_READINESS_V2=1 \
    GJC_SHUTDOWN_TIMEOUT_MS=15000

USER 1004:1004
ENTRYPOINT ["/usr/bin/tini", "--", "bun", "/app/daemon/src/container-entrypoint.js"]
