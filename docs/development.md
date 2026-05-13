## Overview

This document serves as guide how to effectively work with crypto-broker-server locally.

### Prerequisites

Note that you need to have a version of [Golang](https://go.dev/doc/install) > 1.24 installed on your local machine in order to run it locally from terminal. For building the Docker image, you need to have Docker/Docker Desktop or any other alternative (e.g. Podman) installed.

For running the commands using the `Taskfile` tool, you need to have Taskfile installed. Please check the documentation on [how to install Taskfile](https://taskfile.dev/installation/). If you don't have Taskfile support, you can directly use the commands specified in the Taskfile on your local terminal, provided you meet the requirements.
Please note, that `Taskfile` may use `.env` file as source of environment variables. For convenience, please copy `.env.example` file into `.env` and adjust env variables.

To contribute to this project please configure the custom githooks for this project:

```bash
git config core.hooksPath .githooks
```

This commit hook will make sure the code follows the standard formatting and keep everything consistent.

Additionally, please download all required tools for project development.
Please inspect the different tasks of [tools](./Taskfile.yaml) for more information which Go modules will be downloaded and installed.
Installation of the necessary tools is supported automatically for Linux and macOS.

```bash
task tools
```

### Building

#### Compiling the binary file

To build server binary in the `/bin` directory use

```shell
task build
```

This will also save a checksum of all the file `sources` in the Taskfile cache `.task`.
This means that, if no new changes are done, re-running the task will not build the binary again.

This repository uses a submodule for the proto files in `/protobuf` directory.

To reload the `/protobuf` files to the latest `main` commit and recompile them, run the following:

```shell
task proto
```

#### Building the Docker image

For building the image for local use, you can use the command:

```shell
task build-docker [TAG=opt]
```

The TAG argument is optional and will apply a custom image tag to the built images. If not specified, it defaults to `latest`. This will create a local image tagged as `server_app:TAG`, which will be saved in your local Docker repository. If you want to modify or append args to the build command, please refer to the one from the Taskfile.

Note that, by default, Taskfile will import a local `.env` file located in the directory. This is optional and  can be used to push images to private repositories or injecting variables in the system.

### Testing

The server is meant to be tested using the standard Golang Testing `go test`. If you want to additionally invoke the local pipeline for code formatting, you can run all of these commands with:

```shell
task ci
```

To run benchmarks, run

```shell
task run-benchmarks
```

More info on benchmarks can be found in [testing](https://pkg.go.dev/testing@go1.25.3#hdr-Benchmarks) pkg. For detailed description of bench output see [proposal](https://go.googlesource.com/proposal/+/master/design/14313-benchmark-format.md).

For some of benchmarks, you need to have the [deployment repository](https://github.com/open-crypto-broker/crypto-broker-deployment) in the same parent directory as this repository.

For running the server locally (e.g. for testing with the libraries' CLI), change directory to project root & run server with following command. This will first [compile the Go Code](#compiling-the-binary-file) if any of the Go files have been changed and then run the server with the default profiles dir:

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