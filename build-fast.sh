#!/usr/bin/env bash
# =============================================================================
# Fast Native Build Script for beecd services
# =============================================================================
# This script builds services natively on your Mac (ARM64), avoiding the slow
# QEMU emulation in Docker. For production amd64 images, it uses cross-rs
# which is significantly faster than Docker QEMU emulation.
#
# Usage:
#   ./build-fast.sh agent          # Build agent only
#   ./build-fast.sh hive           # Build hive only  
#   ./build-fast.sh hive-hq        # Build hive-hq only
#   ./build-fast.sh all            # Build all services
#   ./build-fast.sh agent --native # Build for native arch (fastest for dev)
#   ./build-fast.sh agent --push   # Build and push to registry
#
# Requirements:
#   - Rust toolchain (rustup)
#   - cross (cargo install cross)
#   - Docker (for final image creation)
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
REGISTRY="${REGISTRY:-registry:5000}"
VERSION=$(grep -E '^version' Cargo.toml | head -1 | sed -E 's/version = "(.*)"/\1/')
TIMESTAMP=$(date +"%Y%m%d%H%M%S")
GIT_HASH=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")

# Detect host architecture
HOST_ARCH=$(uname -m)
if [[ "$HOST_ARCH" == "arm64" || "$HOST_ARCH" == "aarch64" ]]; then
    NATIVE_TARGET="aarch64-unknown-linux-musl"
    CROSS_TARGET="x86_64-unknown-linux-musl"
else
    NATIVE_TARGET="x86_64-unknown-linux-musl"
    CROSS_TARGET="aarch64-unknown-linux-musl"
fi

# Default to cross-compiled amd64 for production
TARGET="${CROSS_TARGET}"
PLATFORM="linux/amd64"
USE_NATIVE=false
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
  --native      Build for native architecture (fastest, for local dev)
  --amd64       Build for linux/amd64 (default, for production)
  --arm64       Build for linux/arm64
  --dev         Add dev tag (timestamp + git hash)
  --push        Push image to registry after build
  --help        Show this help message

Examples:
  $0 agent --native           # Fast local dev build
  $0 agent --dev --push       # Dev build + push to registry
  $0 all --native             # Build all services for local testing
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
        --native)
            USE_NATIVE=true
            TARGET="$NATIVE_TARGET"
            if [[ "$HOST_ARCH" == "arm64" || "$HOST_ARCH" == "aarch64" ]]; then
                PLATFORM="linux/arm64"
            else
                PLATFORM="linux/amd64"
            fi
            shift
            ;;
        --amd64)
            TARGET="x86_64-unknown-linux-musl"
            PLATFORM="linux/amd64"
            shift
            ;;
        --arm64)
            TARGET="aarch64-unknown-linux-musl"
            PLATFORM="linux/arm64"
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

#######################################
# Check prerequisites
#######################################
check_prerequisites() {
    log_info "Checking prerequisites..."
    
    if ! command -v rustup &>/dev/null; then
        log_error "rustup not found. Please install Rust: https://rustup.rs"
        exit 1
    fi
    
    if ! command -v cargo &>/dev/null; then
        log_error "cargo not found"
        exit 1
    fi
    
    # Check if target is installed
    if ! rustup target list --installed | grep -q "$TARGET"; then
        log_info "Installing Rust target: $TARGET"
        rustup target add "$TARGET"
    fi
    
    # For cross-compilation, check if cross is needed
    if [[ "$USE_NATIVE" == false ]]; then
        if ! command -v cross &>/dev/null; then
            log_warn "cross not found. Installing..."
            cargo install cross --git https://github.com/cross-rs/cross
        fi
    fi
    
    if ! command -v docker &>/dev/null; then
        log_error "Docker not found"
        exit 1
    fi
    
    log_success "Prerequisites OK"
}

#######################################
# Setup OpenSSL for musl builds
#######################################
setup_openssl() {
    local ssl_dir="$SCRIPT_DIR/.build-cache/openssl-musl-${TARGET}"
    
    if [[ -d "$ssl_dir" && -f "$ssl_dir/lib/libssl.a" ]]; then
        log_info "Using cached OpenSSL from $ssl_dir"
        export OPENSSL_DIR="$ssl_dir"
        export OPENSSL_STATIC=1
        return 0
    fi
    
    # For native builds, we can use the system OpenSSL via pkg-config
    # or build a cached version
    if [[ "$USE_NATIVE" == true ]]; then
        log_info "For native builds, using vendored OpenSSL feature"
        export OPENSSL_STATIC=1
        return 0
    fi
    
    # For cross builds, cross-rs handles OpenSSL
    return 0
}

#######################################
# Set build tag
#######################################
if [[ "$DEV_BUILD" == true ]]; then
    export BUILD_VERSION="${VERSION}-dev-${TIMESTAMP}-${GIT_HASH}"
else
    export BUILD_VERSION="${VERSION}"
fi 


#######################################
# Build a service binary
#######################################
build_binary() {
    local service="$1"
    local package="$service"
    
    # Map service names to cargo package names
    case "$service" in
        hive-hq) package="api" ;;
    esac
    
    log_info "Building $service for target $TARGET..."
    
    local start_time=$(date +%s)
    
    if [[ "$USE_NATIVE" == true ]]; then
        # Native build - fastest option
        log_info "Using native cargo build"
        
        # Check if we need musl-cross for linking
        if [[ "$TARGET" == *"musl"* ]]; then
            # Try to use vendored OpenSSL to avoid musl complications
            CARGO_ARGS="--features openssl/vendored"
        fi
        
        cargo build --release --target "$TARGET" -p "$package" ${CARGO_ARGS:-}
    else
        # Cross-compilation using cross-rs (much faster than Docker QEMU)
        log_info "Using cross for cross-compilation"
        cross build --release --target "$TARGET" -p "$package"
    fi
    
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    log_success "Binary built in ${duration}s"
}

#######################################
# Build hive-hq UI (requires npm)
#######################################
build_hive_hq_assets() {
    log_info "Building hive-hq UI..."
    
    # Check for npm
    if ! command -v npm &>/dev/null; then
        log_error "npm not found. Please install Node.js: https://nodejs.org"
        exit 1
    fi
    
    # Build UI with npm/vite (React)
    log_info "Building UI with npm (React/Vite)..."
    (cd hive-hq/ui && npm ci && npm run build)
    
    # Copy dist to hive-hq/dist for consistency with Docker build
    rm -rf hive-hq/dist
    cp -r hive-hq/ui/dist hive-hq/dist
    
    log_success "UI built"
}

#######################################
# Create Docker image from pre-built binary
#######################################
create_docker_image() {
    local service="$1"
    local binary_name="$service"
    local image_name="$service"
    
    # Map service names
    case "$service" in
        hive-hq)
            binary_name="api"
            image_name="hive-hq"
            ;;
        hive)
            binary_name="hive"
            image_name="hive-server"
            ;;
        agent)
            binary_name="agent"
            image_name="hive-agent"
            ;;
    esac
    
    local tag="$BUILD_VERSION"
    local full_image="${REGISTRY}/${image_name}:${tag}"
    local latest_image="${REGISTRY}/${image_name}:latest"
    
    log_info "Creating Docker image: $full_image"
    
    # Create a minimal Dockerfile for packaging
    local tmp_dockerfile=$(mktemp)
    
    if [[ "$service" == "hive-hq" ]]; then
        # hive-hq needs UI assets
        cat > "$tmp_dockerfile" <<EOF
FROM alpine:3.19.1
RUN apk add --no-cache ca-certificates
COPY ${binary_name} /usr/local/bin/${binary_name}
COPY dist dist
CMD ["${binary_name}"]
EOF
    else
        cat > "$tmp_dockerfile" <<EOF
FROM alpine:3.19.1
RUN apk add --no-cache ca-certificates
COPY ${binary_name} /usr/local/bin/${binary_name}
CMD ["${binary_name}"]
EOF
    fi
    
    # Copy binary to temp location for Docker context
    local binary_path="target/${TARGET}/release/${binary_name}"
    if [[ ! -f "$binary_path" ]]; then
        log_error "Binary not found: $binary_path"
        rm "$tmp_dockerfile"
        return 1
    fi
    
    local tmp_dir=$(mktemp -d)
    cp "$binary_path" "$tmp_dir/${binary_name}"
    cp "$tmp_dockerfile" "$tmp_dir/Dockerfile"
    
    # For hive-hq, also copy UI assets
    if [[ "$service" == "hive-hq" ]]; then
        if [[ ! -d "hive-hq/dist" ]]; then
            log_error "UI dist not found. Run build_hive_hq_assets first."
            rm -rf "$tmp_dir" "$tmp_dockerfile"
            return 1
        fi
        cp -r hive-hq/dist "$tmp_dir/dist"
    fi
    
    # Build the minimal image
    docker build \
        --platform "$PLATFORM" \
        -t "$full_image" \
        -t "$latest_image" \
        "$tmp_dir"
    
    rm -rf "$tmp_dir" "$tmp_dockerfile"
    
    log_success "Created image: $full_image"
    
    # Push if requested
    if [[ "$PUSH_IMAGE" == true ]]; then
        log_info "Pushing image..."
        docker push "$full_image"
        docker push "$latest_image"
        log_success "Pushed image"
    fi
}

#######################################
# Build a single service
#######################################
build_service() {
    local service="$1"
    
    log_info "=========================================="
    log_info "Building service: $service"
    log_info "Target: $TARGET"
    log_info "Platform: $PLATFORM"
    log_info "=========================================="
    
    local start_time=$(date +%s)
    
    # For hive-hq, build UI and docs first
    if [[ "$service" == "hive-hq" ]]; then
        build_hive_hq_assets
    fi
    
    build_binary "$service"
    create_docker_image "$service"
    
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    log_success "Service $service completed in ${duration}s"
}

#######################################
# Main
#######################################
main() {
    log_info "Fast Build Script for beecd"
    log_info "Host architecture: $HOST_ARCH"
    log_info "Target: $TARGET"
    log_info "Native build: $USE_NATIVE"
    
    check_prerequisites
    setup_openssl
    
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
