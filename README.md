# Crypto Broker Server

This repository contains the Crypto Broker server that allows the user to perform cryptographic operations. The server is not intended to be used alone, but in combination with any of the libraries provided.

## Usage

### Installation

The server does not need to be integrated into any existing code. Instead, it is meant to be deployed as a sidecar to a main application using the client library to communicate with the server. Client and server will establish a communication via a Unix Socket over a local shared drive (fixed to `/tmp`) and exchange data via gRPC as communication protocol.

### Usage

The server is not mean to be run locally in production. However, this can be done for the sake of easier testing. For that, please refer to the section below of [Testing](#testing).

At the moment, two methods of deployment are supported:

* CloudFoundry: Using the binaries provided in the [Releases](https://github.com/open-crypto-broker/crypto-broker-server/releases)
* Kubernetes: Using the Docker Image of the server

Documentation on how to deploy the server on these methods can be found on the [deployment repository](https://github.com/open-crypto-broker/crypto-broker-deployment)

## Development

This section covers how to contribute to the project and develop it further.

### Prerequisites

Note that you need to have a version of [Golang](https://go.dev/doc/install) > 1.24 installed on your local machine in order to run it locally from terminal. For building the Docker image, you need to have Docker/Docker Desktop or any other alternative (e.g. Podman) installed.

For running the commands using the `Taskfile` tool, you need to have Taskfile installed. Please check the documentation on [how to install Taskfile](https://taskfile.dev/installation/). If you don't have Taskfile support, you can directly use the commands specified in the Taskfile on your local terminal, provided you meet the requirements.

To contribute to this project please configure the custom githooks for this project:

```bash
git config core.hooksPath .githooks
```

This commit hook will make sure the code follows the standard formatting and keep everything consistent.

### Building

#### Compiling the binary file

To build server binary in the `/bin` directory use

```shell
task build-go
```

This will also save a checksum of all the file `sources` in the Taskfile cache `.task`. This means that, if no new changes are done, re-running the task will not build the binary again. For building the binaries for few other architectures, use the other command:

```shell
task build-arch
```

This repository uses a submodule for the proto files in `/protobuf` directory.

To reload the `/protobuf` files to the latest `main` commit and recompile them, run the following:

```shell
task proto
```

#### Building the Docker image

For building the image for local use, you can use the command:

```shell
task build [TAG=opt]
```

The TAG argument is optional and will apply a custom image tag to the built images. If not specified, it defaults to `latest`. This will create a local image tagged as `server_app:TAG`, which will be saved in your local Docker repository. If you want to modify or append args to the build command, please refer to the one from the Taskfile.

Note that, by default, Taskfile will import a local `.env` file located in the directory. This is optional and  can be used to push images to private repositories or injecting variables in the system.

### Testing

The server is meant to be tested using the standard Golang Testing `go test`. If you want to additionally invoke the local pipeline for code formatting, you can run all of these commands with:

```shell
task ci
```

For running the server locally (e.g. for testing with the libraries' CLI), change directory to project root & run server with following command. This will first [compile the Go Code](#compiling-the-go-binaries) if any of the Go files have been changed and then run the server with the default profiles dir:

```shell
task run
```

If you want to define your custom profiles dir, you can directly run the server with the following command:

```shell
CRYPTO_BROKER_PROFILES_DIR=<path-to-your-Profile.yaml> go run cmd/server/server.go
```

Both commands will keep the server running and listening on the unix socket. From another terminal in localhost, you can run the libraries' CLI in order to perform a local end2end test. For a more thorough end2end test, check the deployment repository.

#### Debugging with VS Code

To run & debug in `VSCode`:

1. Create `.vscode` secret directory in root of repository
1. Create `launch.json` file in it
1. Fill it with:

```json
{
    "version": "0.2.0",
    "configurations": [
        {
            "name": "Launch Package",
            "type": "go",
            "request": "launch",
            "mode": "auto",
            "console": "integratedTerminal",
            "program": "${workspaceFolder}/cmd/server/server.go",
            "env": {
                "CRYPTO_BROKER_PROFILES_DIR": "${workspaceFolder}/profiles"
            },
            "args": ""
        }
    ]
}
```

Open `Run and Debug` tab from left side nav bar.
Click on `Start Debugging` icon.

Now you can place breakpoints in your code.

## Security / Disclosure

If you find any bug that may be a security problem, please follow our instructions at in our [security policy](./SECURITY.md) on how to report it. Please do not create GitHub issues for security-related doubts or problems.

## Code of Conduct

We as members, contributors, and leaders pledge to make participation in our community a harassment-free experience for everyone. By participating in this project, you agree to abide by its [Code of Conduct](https://github.com/open-crypto-broker/.github/blob/main/CODE_OF_CONDUCT.md) at all times.

## Licensing

Copyright 2025 SAP SE or an SAP affiliate company and Open Crypto Broker contributors. Please see our [LICENSE](./LICENSE) for copyright and license information. Detailed information including third-party components and their licensing/copyright information is available via the [REUSE](REUSE.toml) tool.
