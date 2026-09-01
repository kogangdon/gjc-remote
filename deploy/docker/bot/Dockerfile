# syntax=docker/dockerfile:1.7

ARG BUN_IMAGE=oven/bun:1.3.14@sha256:e10577f0db68676a7024391c6e5cb4b879ebd17188ab750cf10024a6d700e5c4
ARG NODE_IMAGE=node:26.8.1-trixie-slim@sha256:c0753125a3789977aefe869cbebccf70e3cfd7ea84ca48547458f02e4f1d7146

FROM ${BUN_IMAGE} AS deps
WORKDIR /app
COPY package.json bun.lock ./
COPY bot/package.json ./bot/package.json
COPY daemon/package.json ./daemon/package.json
COPY native-control/package.json ./native-control/package.json
COPY shared/package.json ./shared/package.json
RUN bun install --frozen-lockfile --production --ignore-scripts \
      --filter @gjc-remote/bot

# Production builds MUST provide this named BuildKit context. Its root contains
# native_control.node, native-control.manifest.json, and
# native-control.manifest.json.sig from the external release-signing flow.
FROM native_control_bundle AS signed-native

FROM ${NODE_IMAGE} AS runtime
ARG VERSION=0.3.1
ARG REVISION=unknown
LABEL org.opencontainers.image.title="gjc-remote bot" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.source="https://github.com/kogangdon/gjc-remote"

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates libacl1 tini \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY bot ./bot
COPY native-control/package.json ./native-control/package.json
COPY native-control/src ./native-control/src
COPY native-control/scripts ./native-control/scripts
COPY native-control/release-keys ./native-control/release-keys
COPY shared ./shared
COPY --chmod=0444 --from=signed-native /native_control.node ./native-control/build/Release/native_control.node
COPY --chmod=0444 --from=signed-native /native-control.manifest.json ./native-control/build/Release/native-control.manifest.json
COPY --chmod=0444 --from=signed-native /native-control.manifest.json.sig ./native-control/build/Release/native-control.manifest.json.sig
RUN chmod 0555 ./native-control/build ./native-control/build/Release

# This loads the platform-matched addon and verifies its committed contract,
# digest, manifest, and production signature. Unsigned/self-signed bundles fail
# the image build; the Dockerfile never compiles a replacement after signing.
RUN node native-control/scripts/verify-build.mjs --require-signature

ENV NODE_ENV=production \
    HOST_WS_PORT=7711 \
    CHANNELS_CONFIG=/var/lib/gjc-remote/channels.json

EXPOSE 7711
USER node
HEALTHCHECK --interval=30s --timeout=3s --start-period=15s --retries=3 \
  CMD ["node", "/app/bot/src/container-healthcheck.js"]
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["node", "/app/bot/src/bot.js"]
