#!/bin/sh

# Call gRPC service and capture JSON output
output=$(grpcurl -proto health.proto -plaintext -d '{"service":""}' unix:/tmp/open-crypto-broker/cryptobroker.sock grpc.health.v1.Health/Check 2>/dev/null)

# Extract the "status" field using grep + sed
status=$(echo "$output" | grep -o '"status"[[:space:]]*:[[:space:]]*"[^"]*"' | sed 's/.*: *"\(.*\)"/\1/')

# Check the status and return code
if [ "$status" = "SERVING" ]; then
  exit 0
else
  exit 1
fi
