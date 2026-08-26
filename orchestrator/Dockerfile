# Multi-stage build: static Go binary, scratch runtime.
# The orchestrator must run as ROOT (it creates host users via useradd and
# talks to docker.sock). Runtime deps are the docker CLI passthrough only if
# needed; base image is kept minimal.

FROM golang:1.26 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/orchestrator ./cmd/orchestrator

FROM debian:bookworm-slim AS runtime
RUN apt-get update && apt-get install -y --no-install-recommends passwd ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/orchestrator /usr/local/bin/orchestrator
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/orchestrator"]
