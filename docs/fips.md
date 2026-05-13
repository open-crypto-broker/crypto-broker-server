## Overview

This document describes what is FIPS compliance and how you can use it within `crypto-broker-server` component.

### What is FIPS

National Institute of Standards and Technology FIPS stands for Federal Information Processing Standards. These are U.S. government standards published by NIST for computer systems used by federal agencies.

FIPS140-3 define security requirements for cryptographic modules — libraries or components that perform encryption, hashing, signing, key generation, etc.

### How go implements FIPS 140-3

FIPS is a government certification standard. So “Golang FIPS compliance” refers to the process of making Go cryptography use a FIPS-validated module.

Please read following official docs to learn more:

* [FIPS 140-3 Compliance](https://go.dev/doc/security/fips140)
* [The FIPS 140-3 Go Cryptographic Module](https://go.dev/blog/fips140)
* [Go Cryptography Security Audit](https://go.dev/blog/tob-crypto-audit)

### How `crypto-broker-server` works with FIPS

General description can be found in "A native developer experience" section of [this](https://go.dev/blog/fips140#a-native-developer-experience) article.  

#### Locally

Locally, developer is encouraged to use [Taskfile](./../Taskfile.yaml). Taksfile uses `.env` file (please see [.env.example](./../.env.example)) to read environment variables (please distinguish [environment variables](./envs.md) read by server binary from those read by Taskfile).
Following environment variables can be used related with FIPS concept:

| Variable | Default | Description | Valid Values |
| -------- | ------- | ----------- | ------------ |
| `FIPS_MODE_ENABLED` | - | Whether to enable FIPS mode | "true" or "false" |
| `FIPS_MODE_MODULE_VERSION` | - | Version of the FIPS mode module to use | "v1.0.0", ... |
| `FIPS_GODEBUG_VALUE` | - | Value of the GODEBUG environment variable to use when FIPS mode is enabled | "fips140=on", "fips140=only", "fips140=off" |

Please note that `FIPS_GODEBUG_VALUE` equal to `fips140=only` restrics Go program to allow only FIPS140 compliant operations (and therefore algorithms).
Server has built-in recover middleware, therefore any panic that would occur from Go in that mode will be changed to server error that may look like this:

```
crypto/md5: use of MD5 is not allowed in FIPS 140-only mode 
```

Therefore server will not exit even with usage of non-compliant algorithm.
