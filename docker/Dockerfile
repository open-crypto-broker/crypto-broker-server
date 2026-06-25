## This Dockerfile builds the Crypto Broker Server

ARG GO_VERSION=1.26
ARG ALPINE_VERSION=3.24
ARG GRPC_HEALTH_PROBE_VERSION=v0.4.52

## Build
FROM golang:${GO_VERSION}-alpine${ALPINE_VERSION} AS build

WORKDIR /app

# Install git for go install / module fetching
RUN apk add --no-cache git

COPY go.mod ./
COPY go.sum ./

RUN  go mod download

COPY . .

RUN CGO_ENABLED=0 go build -o app ./cmd/server

## Redeclare GRPC_HEALTH_PROBE_VERSION
ARG GRPC_HEALTH_PROBE_VERSION
## Install grpc-health-probe for health checks
RUN CGO_ENABLED=0 go install github.com/grpc-ecosystem/grpc-health-probe@${GRPC_HEALTH_PROBE_VERSION}

## Deploy with scratch docker image (no other binaries, dependencies, etc)
FROM scratch

WORKDIR /app

# Copy server and profile
COPY --from=build /app/app .
COPY --from=build /app/example-profiles ./profiles
# Healthcheck: use grpc-health-probe to check the gRPC health endpoint
COPY --from=build /go/bin/grpc-health-probe /usr/local/bin/grpc-health-probe

ENTRYPOINT ["./app"]

HEALTHCHECK --interval=10s --timeout=3s --retries=3 \
  CMD ["/usr/local/bin/grpc-health-probe", "-addr", "unix:///tmp/open-crypto-broker/crypto-broker-server.sock"]
