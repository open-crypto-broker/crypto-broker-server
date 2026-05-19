# Crypto Broker Server

This repository contains the Crypto Broker server that allows the user to perform cryptographic operations. The server is not intended to be used alone, but in combination with any of the libraries provided.

## Usage

The server does not need to be integrated into any existing code. Instead, it is meant to be deployed as a sidecar to a main application using the client library to communicate with the server. Client and server will establish a communication via a Unix Socket over a local shared drive (fixed to `/tmp/open-crypto-broker`) and exchange data via gRPC as communication protocol.

The server is not mean to be run locally in production. However, this can be done for the sake of easier testing. For that, please refer to the testing section of [development guide](./docs/development.md#testing).

At the moment, two methods of deployment are supported:

* CloudFoundry: Using the binaries provided in the [Releases](https://github.com/open-crypto-broker/crypto-broker-server/releases)
* Kubernetes: Using the Docker Image of the server

Documentation on how to deploy the server on these methods can be found on the [deployment repository](https://github.com/open-crypto-broker/crypto-broker-deployment)

### Environment Variables

The Crypto Broker Server supports several environment variables for configuration. [Please read environment variables table](./docs/envs.md) to understand them in detail.

### FIPS compliance

Goal of `crypto-broker-server` is to be FIPS compliant. [click here for more info](./docs/fips.md) to learn how to utilize it.

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
