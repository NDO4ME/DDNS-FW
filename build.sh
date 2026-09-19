#!/bin/bash
set -e

VERSION=$(grep '^version' Cargo.toml | head -1 | cut -d'"' -f2)
DIST_DIR="dist"

echo "Building DDNS-FW v${VERSION} for all architectures..."
echo ""

# Create dist directory
rm -rf "$DIST_DIR"
mkdir -p "$DIST_DIR"

# Targets to build
declare -A TARGETS=(
    ["x86_64-unknown-linux-musl"]="x86_64"
    ["aarch64-unknown-linux-musl"]="aarch64"
    ["armv7-unknown-linux-musleabihf"]="armv7"
    ["i686-unknown-linux-musl"]="i686"
)

for target in "${!TARGETS[@]}"; do
    arch="${TARGETS[$target]}"
    output_name="ddnsfw-v${VERSION}-linux-${arch}"

    echo "Building for ${arch} (${target})..."

    if cargo build --release --target "$target" 2>/dev/null; then
        cp "target/${target}/release/ddnsfw" "${DIST_DIR}/${output_name}"
        size=$(du -h "${DIST_DIR}/${output_name}" | cut -f1)
        echo "  -> ${output_name} (${size})"
    else
        echo "  -> FAILED (missing toolchain or linker for ${target})"
    fi
done

echo ""
echo "Build complete. Binaries in ${DIST_DIR}/:"
ls -lh "$DIST_DIR/"
