## This Dockerfile builds server

## use grpcurl tool for health checks
FROM fullstorydev/grpcurl:latest AS grpcurl

## Build
FROM golang:alpine AS build

WORKDIR /app

COPY go.mod ./
COPY go.sum ./

RUN  go mod download

COPY . .

RUN go build -o app ./cmd/server

## Deploy
FROM alpine

WORKDIR /app

# copy the server and profiles
COPY --from=build /app/app .
COPY --from=build /app/example-profiles ./profiles

# healthcheck: copy proto, grpcurl and health status script
COPY --from=build /app/protobuf/third_party/grpc/health/v1/health.proto .
COPY --from=build /app/docker/health_status.sh .
COPY --from=grpcurl /bin/grpcurl /usr/local/bin/grpcurl

ENTRYPOINT ["./app"]
HEALTHCHECK CMD ./health_status.sh || exit 1
