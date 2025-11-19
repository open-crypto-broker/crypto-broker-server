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

WORKDIR /app

COPY --from=build /app/app .
COPY --from=build /app/example-profiles ./profiles

ENTRYPOINT ["./app"]
