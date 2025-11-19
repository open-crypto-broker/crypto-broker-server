## This Dockerfile builds server

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

ARG CRYPTO_BROKER_PROFILES_DIR

WORKDIR /app

COPY --from=build /app/app .
COPY --from=build /app/${CRYPTO_BROKER_PROFILES_DIR} ./profiles

ENTRYPOINT ["./app"]
