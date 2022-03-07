#!/bin/bash

set -e

DIR=$(dirname $(readlink -f ${BASH_SOURCE[0]}))
export SPIFF_FEATURES=interpolation

#lib=~/dev/go/spiff/src/github.com/mandelsoft/spiff/libraries
# use libs form spiff project
lib=https://raw.githubusercontent.com/mandelsoft/spiff/dev/libraries
stubs=( "$lib/state/state.yaml" "$lib/certs/certs.yaml" "$lib/generate/generate.yaml" )
spiff merge --state state.yaml "$DIR/manifests.yaml" "${stubs[@]}"
