#!/usr/bin/env bash
# =============================================================================
# Docker Build Script for beecd services
# =============================================================================
# Uses Docker BuildKit with cross-compilation for linux/amd64 and linux/arm64
#
# Usage:
#   ./build.sh agent                    # Build agent only
#   ./build.sh hive                     # Build hive only
#   ./build.sh hive-hq                  # Build hive-hq only
#   ./build.sh all                      # Build all services
#   ./build.sh agent --dev              # Build with dev tag
#   ./build.sh agent --push             # Build and push to registry
#   ./build.sh all --dev --push         # Build all, dev tags, and push
#
# Environment:
#   REGISTRY=codeberg.org/user/repo ./build.sh agent
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

# Enable BuildKit
export DOCKER_BUILDKIT=1

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
DEFAULT_REGISTRY="${REGISTRY:-registry:5000}"
REGISTRIES=()
VERSION=$(grep -E '^version' Cargo.toml | head -1 | sed -E 's/version = "(.*)"/\1/')
TIMESTAMP=$(date +"%Y%m%d%H%M%S")
GIT_HASH=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")

PUSH_IMAGE=false
DEV_BUILD=false
SERVICES=()

#######################################
# Logging helpers
#######################################
log_info() { echo -e "${BLUE}[INFO]${NC} $*"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $*"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*" >&2; }

#######################################
# Usage
#######################################
usage() {
    cat <<EOF
Usage: $0 <service|all> [options]

Services:
  agent         Build the agent service
  hive          Build the hive service
  hive-hq       Build the hive-hq service
  all           Build all services

Options:
  --dev         Add dev tag (timestamp + git hash)
  --push        Push image to registry after build
  --registry    Specify registry (repeatable, or comma-separated)
                Default: ${DEFAULT_REGISTRY}
  --help        Show this help message

Examples:
  $0 agent                                    # Build agent locally
  $0 agent --dev --push                       # Dev build + push
  $0 all --push                               # Build all and push
  $0 agent --registry foo:3002/bar --registry registry:5000
  $0 all --registry foo:3002/bar,registry:5000,docker.io/user --push
EOF
    exit 1
}

#######################################
# Parse arguments
#######################################
while [[ $# -gt 0 ]]; do
    case "$1" in
        agent|hive|hive-hq|all)
            if [[ "$1" == "all" ]]; then
                SERVICES=(agent hive hive-hq)
            else
                SERVICES+=("$1")
            fi
            shift
            ;;
        --dev)
            DEV_BUILD=true
            shift
            ;;
        --push)
            PUSH_IMAGE=true
            shift
            ;;
        --registry)
            # Support comma-separated or repeated --registry
            IFS=',' read -ra NEW_REGISTRIES <<< "$2"
            for r in "${NEW_REGISTRIES[@]}"; do
                REGISTRIES+=("$r")
            done
            shift 2
            ;;
        --help|-h)
            usage
            ;;
        *)
            log_error "Unknown option: $1"
            usage
            ;;
    esac
done

if [[ ${#SERVICES[@]} -eq 0 ]]; then
    log_error "No service specified"
    usage
fi

# Use default registry if none specified
if [[ ${#REGISTRIES[@]} -eq 0 ]]; then
    REGISTRIES=("$DEFAULT_REGISTRY")
fi

# Remove duplicate registries
REGISTRIES=($(printf "%s\n" "${REGISTRIES[@]}" | awk '!seen[$0]++'))

#######################################
# Set build tag
#######################################
if [[ "$DEV_BUILD" == true ]]; then
    export BUILD_VERSION="${VERSION}-dev-${TIMESTAMP}-${GIT_HASH}"
else
    export BUILD_VERSION="${VERSION}"
fi

#######################################
# Build a service with Docker
#######################################
build_service() {
    local service="$1"
    local image_name="$service"

    # Map service names to image names
    case "$service" in
        hive) image_name="hive-server" ;;
        agent) image_name="hive-agent" ;;
        hive-hq) image_name="hive-hq" ;;
    esac

    local tag="$BUILD_VERSION"

    # Build tag arguments for all registries
    local tag_args=()
    for registry in "${REGISTRIES[@]}"; do
        tag_args+=("--tag" "${registry}/${image_name}:${tag}")
        tag_args+=("--tag" "${registry}/${image_name}:latest")
    done

    log_info "=========================================="
    log_info "Building service: $service"
    log_info "Registries: ${REGISTRIES[*]}"
    log_info "=========================================="

    local start_time=$(date +%s)

    # For multi-arch, we can't use --load, so we either push or export
    local build_opts=()
    if [[ "$PUSH_IMAGE" == true ]]; then
        build_opts+=("--push")
    else
        log_warn "Multi-arch build without --push will not load images locally"
        log_warn "Images will only be cached. Use --push to push to registry."
    fi

    # Build once with all tags
    docker buildx build \
        --platform linux/amd64,linux/arm64 \
        --build-arg BUILD_VERSION="$BUILD_VERSION" \
        --file "${service}/Dockerfile" \
        "${tag_args[@]}" \
        "${build_opts[@]}" \
        .

    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    log_success "Build completed in ${duration}s"
}

#######################################
# Main
#######################################
main() {
    log_info "Docker Build Script for beecd"
    log_info "Registries: ${REGISTRIES[*]}"
    log_info "Version: $BUILD_VERSION"

    local total_start=$(date +%s)

    for service in "${SERVICES[@]}"; do
        build_service "$service"
    done

    local total_end=$(date +%s)
    local total_duration=$((total_end - total_start))

    echo ""
    log_success "=========================================="
    log_success "All builds completed in ${total_duration}s"
    log_success "=========================================="
}

main
