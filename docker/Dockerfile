## This Dockerfile builds the Crypto Broker Server

ARG GO_VERSION=1.27
ARG ALPINE_VERSION=3.24

# Runtime user/group id. Defaults to 1000 (the uid Platform Mesh assigns to the
# sidecar and the owner of the shared Unix socket). Override at build time with
# --build-arg APP_UID=... / APP_GID=... if your environment mandates a different
# uid; the socket directory ownership and the USER directive both follow it.
ARG APP_UID=1000
ARG APP_GID=1000

## Build
# --platform=$BUILDPLATFORM builds on the builder's native architecture and
# cross-compiles to the requested TARGETOS/TARGETARCH (both injected by buildx),
# so a single Dockerfile can produce amd64 and arm64 images.
FROM --platform=$BUILDPLATFORM golang:${GO_VERSION}-alpine${ALPINE_VERSION} AS build

ARG TARGETOS
ARG TARGETARCH
ARG GOFIPS140=off

WORKDIR /app

## Install git for go install / module fetching
RUN apk add --no-cache git

COPY go.mod ./
COPY go.sum ./

RUN  go mod download

COPY . .

# Normalise the profile permissions so they are world-readable and the directory
# is world-traversable. Git does not track the read bit, so a fresh clone can end
# up with group-restricted files; this guarantees the non-root runtime user
# (uid 1000, see USER below) can read them after they are copied into the image.
RUN chmod -R a+rX example-profiles

## Pre-create the Unix domain socket directory so it can be copied into the final
## image with the correct ownership (see the COPY --chown in the scratch stage).
RUN mkdir -p /socket-skel/open-crypto-broker

# -trimpath makes the build reproducible (no local paths baked in); -s -w drop
# the symbol table and debug info to shrink the binary.
RUN CGO_ENABLED=0 \
    GOOS=${TARGETOS:-linux} \
    GOARCH=${TARGETARCH:-amd64} \
    GOFIPS140=${GOFIPS140} \
    go build -trimpath -ldflags="-s -w" -o app ./cmd/server

## Deploy with scratch docker image (no other binaries, dependencies, etc)
FROM scratch

## Bring the runtime uid/gid build args into this stage's scope.
ARG APP_UID
ARG APP_GID

WORKDIR /app

## Copy server and profile
COPY --from=build /app/app .
COPY --from=build /app/example-profiles ./profiles
## The server binds a Unix domain socket in /tmp/open-crypto-broker, a path backed
## by the shared `shared_data` volume that Docker seeds from this image the first
## time the volume is created. Shipping the directory owned by APP_UID/APP_GID lets
## the non-root runtime user create and remove the socket; otherwise the freshly
## created volume is root-owned and bind() fails with "permission denied".
COPY --from=build --chown=${APP_UID}:${APP_GID} /socket-skel/open-crypto-broker /tmp/open-crypto-broker

# Run as a non-root user. In Platform Mesh the operator injects this container as
# the sidecar and overrides the uid to 1000 (the owner of the shared Unix socket),
# so defaulting to 1000 here keeps standalone `docker run` consistent with the
# in-cluster behaviour. Override with --build-arg APP_UID/APP_GID if required.
USER ${APP_UID}:${APP_GID}

ENTRYPOINT ["./app"]
