#!/bin/sh
set -eu
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
SOURCE="$HERE/../gloas-native-integration-v1/native"
export GOROOT="$SOURCE/.toolchain/go"
export GOPATH="$SOURCE/.toolchain/gopath"
export GOCACHE="$SOURCE/.toolchain/go-build"
export GOTOOLCHAIN=local GOWORK=off GOMAXPROCS=8
export GOFLAGS="-buildvcs=false -mod=readonly -toolexec=go_tool_exec.py"
export PATH="$GOROOT/bin:$SOURCE/scripts:$PATH"
export PYTHONOPTIMIZE=0 PYTHONNOUSERSITE=1 PYTHONDONTWRITEBYTECODE=1
unset PYTHONPATH
cd "$HERE/source"
exec "$GOROOT/bin/go" "$@"
