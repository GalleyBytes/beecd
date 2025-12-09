#!/bin/bash
# Usage:
#   ./build.sh                           # Build with default registry
#   ./build.sh --dev                      # Build dev image
#   REGISTRY=codeberg.org/user/repo ./build.sh  # Custom registry
#   ./build.sh --registry codeberg.org/user/repo
#
cd "$(dirname $0)"
export IMAGE_NAME=hive-server
export REGISTRY=${REGISTRY:-registry:5000}
export CARGO_PKG_VERSION_FILE=../Cargo.toml
export DOCKER_BUILD_CONTEXT=".."
eval ../build.sh $@
