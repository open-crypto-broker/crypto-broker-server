## This Dockerfile builds the Crypto Broker Server

ARG GO_VERSION=1.26
ARG ALPINE_VERSION=3.24
ARG GRPC_HEALTH_PROBE_VERSION=v0.4.53

## Build
# --platform=$BUILDPLATFORM builds on the builder's native architecture and
# cross-compiles to the requested TARGETOS/TARGETARCH (both injected by buildx),
# so a single Dockerfile can produce amd64 and arm64 images.
FROM --platform=$BUILDPLATFORM golang:${GO_VERSION}-alpine${ALPINE_VERSION} AS build

ARG TARGETOS
ARG TARGETARCH

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

# -trimpath makes the build reproducible (no local paths baked in); -s -w drop
# the symbol table and debug info to shrink the binary.
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH:-amd64} \
    go build -trimpath -ldflags="-s -w" -o app ./cmd/server

## Redeclare GRPC_HEALTH_PROBE_VERSION
ARG GRPC_HEALTH_PROBE_VERSION
## Install grpc-health-probe for health checks (built for the target arch; the
## `find` normalises the output path, which differs for cross-compiled installs).
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH:-amd64} \
    go install github.com/grpc-ecosystem/grpc-health-probe@${GRPC_HEALTH_PROBE_VERSION} \
 && cp "$(find /go/bin -name grpc-health-probe -type f | head -n1)" /grpc-health-probe

## Deploy with scratch docker image (no other binaries, dependencies, etc)
FROM scratch

WORKDIR /app

## Copy server and profile
COPY --from=build /app/app .
COPY --from=build /app/example-profiles ./profiles
## Healthcheck: use grpc-health-probe to check the gRPC health endpoint
COPY --from=build /grpc-health-probe /usr/local/bin/grpc-health-probe

# Run as a non-root user. In Platform Mesh the operator injects this container as
# the sidecar and overrides the uid to 1000 (the owner of the shared Unix socket),
# so defaulting to 1000 here keeps standalone `docker run` consistent with the
# in-cluster behaviour.
USER 1000:1000

ENTRYPOINT ["./app"]

HEALTHCHECK --interval=10s --timeout=3s --retries=3 \
  CMD ["/usr/local/bin/grpc-health-probe", "-addr", "unix:///tmp/open-crypto-broker/crypto-broker-server.sock"]
