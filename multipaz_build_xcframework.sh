#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MULTIPAZ_DIR="${1:?Usage: $0 /path/to/multipaz [output-directory]}"
NATIVE_LIBS="${MULTIPAZ_DIR}/multipaz-longfellow/src/iosMain/nativeLibs"
OUTPUT_DIR="${2:-${SCRIPT_DIR}/output}"
mkdir -p "${OUTPUT_DIR}"
OUTPUT_DIR="$(cd "${OUTPUT_DIR}" && pwd)"
FRAMEWORK_PATH="${OUTPUT_DIR}/MdocZK.xcframework"

for ARCH in arm64-iphoneos arm64-iphonesimulator x86_64-iphonesimulator; do
    test -f "${NATIVE_LIBS}/${ARCH}/lib/libmdoc_static.a"
done
if [[ -e "${FRAMEWORK_PATH}" ]]; then
    echo "Output already exists: ${FRAMEWORK_PATH}" >&2
    exit 1
fi

TEMP_DIR="$(mktemp -d "${OUTPUT_DIR}/mdoczk.XXXXXX")"
trap 'rm -rf "${TEMP_DIR}"' EXIT

# Multipaz includes zstd in each native static library.
cp "${NATIVE_LIBS}/arm64-iphoneos/lib/libmdoc_static.a" "${TEMP_DIR}/libMdocZK_device.a"
lipo -create \
    "${NATIVE_LIBS}/arm64-iphonesimulator/lib/libmdoc_static.a" \
    "${NATIVE_LIBS}/x86_64-iphonesimulator/lib/libmdoc_static.a" \
    -output "${TEMP_DIR}/libMdocZK_simulator.a"

# Headers are exposed separately by the package's CMdocZK target.
xcodebuild -create-xcframework \
    -library "${TEMP_DIR}/libMdocZK_device.a" \
    -library "${TEMP_DIR}/libMdocZK_simulator.a" \
    -output "${FRAMEWORK_PATH}"

echo "XCFramework created at: ${FRAMEWORK_PATH}"
