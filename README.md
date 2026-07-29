# Crypto Broker Server

This repository contains the Crypto Broker server that allows the user to perform cryptographic operations. The server is not intended to be used alone, but in combination with any of the libraries provided.

## Usage

The server does not need to be integrated into any existing code. Instead, it is meant to be deployed as a sidecar to a main application using the client library to communicate with the server. Client and server will establish a communication via a Unix Socket over a local shared drive (fixed to `/tmp/open-crypto-broker`) and exchange data via gRPC as communication protocol.

The server is not mean to be run locally in production. However, this can be done for the sake of easier testing. For that, please refer to the testing section of [development guide](./docs/development.md#testing).

At the moment, two methods of deployment are supported:

* CloudFoundry: Using the binaries provided in the [Releases](https://github.com/open-crypto-broker/crypto-broker-server/releases)
* Kubernetes: Using the Docker Image of the server

Documentation on how to deploy the server on these methods can be found on the [deployment repository](https://github.com/open-crypto-broker/crypto-broker-deployment)

### Running as a container (non-root)

The Docker image runs as a **non-root** user (uid/gid `1000` by default) to satisfy hardened cluster policies (Kubernetes `restricted` Pod Security, OpenShift SCCs) and the Platform Mesh operator, which injects the server as a sidecar and assigns uid `1000` (the owner of the shared Unix socket). Because of this, there are a few things to know when running the image yourself:

* **Shared socket directory** – The server binds its Unix socket in `/tmp/open-crypto-broker`. The image ships this directory owned by the runtime uid. When you mount a **fresh named volume** at `/tmp` (the recommended setup so clients can reach the socket), Docker seeds it from the image and preserves that ownership, so the server can create and remove the socket.
    * If you mount a **host directory** (bind mount) instead, Docker does **not** apply the image ownership — you must `chown` it to the runtime uid (e.g. `chown 1000:1000 /path/on/host`) or the server fails with `bind: permission denied`.
    * A **pre-existing named volume** created by an older, root-based image keeps its root ownership (Docker only seeds *empty* volumes). Remove it once (`docker volume rm <name>` or `docker compose down -v`) so a fresh, correctly-owned volume is created.
* **Clients must run as the same uid** – The socket is created with mode `0600` (owner-only), so any client connecting over it must run as the **same uid** as the server. The provided Go and JS clients already default to uid `1000`.
* **Profiles must be readable** – `Profiles.yaml` is copied into the image world-readable so the non-root user can load it. If you supply your own profiles via a mount, make sure they are readable by the runtime uid.

#### Changing the uid

If your environment mandates a different uid, rebuild with the `APP_UID` / `APP_GID` build args (this drives both the socket-directory ownership and the `USER` directive):

```bash
docker build -f docker/Dockerfile --build-arg APP_UID=1500 --build-arg APP_GID=1500 -t crypto-broker-server .
```

Rebuild the client images with the **same** `APP_UID` so they can still connect to the socket. Overriding the uid only at runtime (e.g. `docker run --user`) without rebuilding will break socket access, because the baked-in directory ownership no longer matches; in Kubernetes, align it via the pod `securityContext` (`runAsUser`/`fsGroup`) instead.

### Environment Variables

The Crypto Broker Server supports several environment variables for configuration. [Please read environment variables table](./docs/envs.md) to understand them in detail.

### FIPS compliance

Goal of `crypto-broker-server` is to be FIPS compliant. [click here for more info](./docs/fips.md) to learn how to utilize it.

### PGO & profiling

Server can be build with PGO for fine tuning. Please familarize yourself with [pgo](./docs/pgo.md) guide.

## OTEL

`crypto-broker-server` implements OTEL standard for `logs`, `traces` and `metrics` [Click here to learn more](./docs/otel.md).

## Development

This [guide](./docs/development.md) covers how to contribute to the project and develop it further.

## Security / Disclosure

If you find any bug that may be a security problem, please follow our instructions at in our [security policy](./SECURITY.md) on how to report it. Please do not create GitHub issues for security-related doubts or problems.

## Code of Conduct

We as members, contributors, and leaders pledge to make participation in our community a harassment-free experience for everyone. By participating in this project, you agree to abide by its [Code of Conduct](https://github.com/open-crypto-broker/.github/blob/main/CODE_OF_CONDUCT.md) at all times.

## Licensing

Copyright 2025 SAP SE or an SAP affiliate company and Open Crypto Broker contributors. Please see our [LICENSE](./LICENSE) for copyright and license information. Detailed information including third-party components and their licensing/copyright information is available via the [REUSE](REUSE.toml) tool.
