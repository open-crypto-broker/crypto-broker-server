//go:build !dev

package main

import "google.golang.org/grpc"

// Production builds exclude the dev service regardless of the runtime environment.
func registerDevService(_ *grpc.Server) {}
