#!/bin/bash

set -e

#lib=~/dev/go/spiff/src/github.com/mandelsoft/spiff/libraries
# use libs form spiff project
lib=https://raw.githubusercontent.com/mandelsoft/spiff/dev/libraries
stubs=( "$lib/state/state.yaml" "$lib/certs/certs.yaml" "$lib/generate/generate.yaml" )
spiff merge --state state.yaml manifests.yaml "${stubs[@]}"
