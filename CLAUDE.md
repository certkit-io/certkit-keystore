# CLAUDE.md

## Project Overview

certkit-keystore is a Go service for storing private keys on your own infrastructure.  It is meant to integrate with https://certkit.io

## Sister Project
There is another project with similar behavior to what we want this service to have, called CertKit Agent: https://github.com/certkit-io/certkit-agent

It too is a golang project and runs as a service on Linux, Windows and Docker.  The sourcecode should be consulted for pre-existing patterns to copy when similar functionality is needed here.

## Language & Build

- **Language:** Go
- **Build:** `go build ./...`
- **Test:** `go test ./...`
- **Single test:** `go test -run TestName ./path/to/package`
- **Lint:** `go vet ./...`
