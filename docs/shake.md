# SHAKE output size

SHAKE128 and SHAKE256 support a configurable output length for `HashData`.
The profile sets the allowed range in bytes. The request can choose a size
within that range using the optional `output_bytes` field.

```yaml
Settings:
  CryptoLibrary: native
Profiles:
  - Name: Hash-SHAKE256
    API:
      HashData:
        HashAlg: shake-256
        MinOutputBytes: 64
        MaxOutputBytes: 128
```

If `MinOutputBytes` is omitted, it defaults to 32 for SHAKE128 or 64 for
SHAKE256. These minimums provide 128-bit and 256-bit collision security,
respectively, as described in [FIPS 202, Appendix A.1](https://doi.org/10.6028/NIST.FIPS.202).
If `MaxOutputBytes` is omitted, it defaults to the resolved minimum.
A profile with only `HashAlg` therefore permits one output size.

The server rejects a profile at load time if its minimum is below the
algorithm minimum, its maximum exceeds 1024 bytes, or its minimum exceeds
its maximum. Neither field is permitted for fixed-output SHA-2 or SHA-3.

If `output_bytes` is omitted, the server uses the profile minimum. A supplied
size outside the profile range, including explicit zero, returns
`InvalidArgument`. Supplying a size for SHA-2 or SHA-3 also returns
`InvalidArgument`. The server checks the size before allocating the hash output.

The response descriptor records the actual output size in **bits**:
`shake-256/512` means SHAKE256 with 64 bytes of output. A 96-byte request
returns `shake-256/768`. HEX encoding uses two characters per output byte.
Persist the descriptor with the hash.

## Existing hashes

Earlier server versions returned 16 bytes for SHAKE128 and 32 bytes for
SHAKE256. The new defaults return 32 and 64 bytes. Existing stored hashes
will not compare equal to the longer results. Plan a migration for stored
hashes and consumers that expect the old lengths. The new profile limits
do not permit the old short lengths.

See [the profile specification](https://github.com/open-crypto-broker/crypto-broker-documentation/blob/main/spec/0001-profile.md#api-hashdata)
and [profile migration guidance](https://github.com/open-crypto-broker/crypto-broker-documentation/blob/main/adr/overall/0013-profile-change-migration-guidance.md).
A complete example is available in `example-profiles/SHAKE.yaml`.
