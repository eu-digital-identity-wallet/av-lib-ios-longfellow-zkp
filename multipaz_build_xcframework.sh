#!/bin/bash

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_DIR="${SCRIPT_DIR}/output"
FRAMEWORK_NAME="MdocZK"

# Clean up previous builds
rm -rf "${OUTPUT_DIR}"
mkdir -p "${OUTPUT_DIR}/temp"

# Combine device libraries
echo "Combining device libraries..."
libtool -static \
    "${SCRIPT_DIR}/arm64-iphoneos/lib/libmdoc_static.a" \
    "${SCRIPT_DIR}/arm64-iphoneos/lib/libzstd.a" \
    -o "${OUTPUT_DIR}/temp/lib${FRAMEWORK_NAME}_device.a"

# Combine simulator arm64 libraries
echo "Combining simulator arm64 libraries..."
libtool -static \
    "${SCRIPT_DIR}/arm64-iphonesimulator/lib/libmdoc_static.a" \
    "${SCRIPT_DIR}/arm64-iphonesimulator/lib/libzstd.a" \
    -o "${OUTPUT_DIR}/temp/lib${FRAMEWORK_NAME}_sim_arm64.a"

# Combine simulator x86_64 libraries
echo "Combining simulator x86_64 libraries..."
libtool -static \
    "${SCRIPT_DIR}/x86_64-iphonesimulator/lib/libmdoc_static.a" \
    "${SCRIPT_DIR}/x86_64-iphonesimulator/lib/libzstd.a" \
    -o "${OUTPUT_DIR}/temp/lib${FRAMEWORK_NAME}_sim_x86_64.a"

# Create fat binary for simulator
echo "Creating simulator fat binary..."
lipo -create \
    "${OUTPUT_DIR}/temp/lib${FRAMEWORK_NAME}_sim_arm64.a" \
    "${OUTPUT_DIR}/temp/lib${FRAMEWORK_NAME}_sim_x86_64.a" \
    -output "${OUTPUT_DIR}/temp/lib${FRAMEWORK_NAME}_simulator.a"

# Copy headers
cp "${SCRIPT_DIR}/arm64-iphoneos/include/"* "${OUTPUT_DIR}/temp/device-headers/"
cp "${SCRIPT_DIR}/arm64-iphonesimulator/include/"* "${OUTPUT_DIR}/temp/simulator-headers/"

# Create module map for device
cat > "${OUTPUT_DIR}/temp/device-headers/module.modulemap" <<EOF
module ${FRAMEWORK_NAME} {
    header "../mdoc_zk.h"
    export *
}
EOF

# Create module map for simulator
cat > "${OUTPUT_DIR}/temp/simulator-headers/module.modulemap" <<EOF
module ${FRAMEWORK_NAME} {
    header "../mdoc_zk.h"
    export *
}
EOF

# Create XCFramework
echo "Creating XCFramework..."
xcodebuild -create-xcframework \
    -library "${OUTPUT_DIR}/temp/lib${FRAMEWORK_NAME}_device.a" \
    -headers "${OUTPUT_DIR}/temp/device-headers" \
    -library "${OUTPUT_DIR}/temp/lib${FRAMEWORK_NAME}_simulator.a" \
    -headers "${OUTPUT_DIR}/temp/simulator-headers" \
    -output "${OUTPUT_DIR}/${FRAMEWORK_NAME}.xcframework"

# Clean up temp files
rm -rf "${OUTPUT_DIR}/temp"

echo "✅ XCFramework created successfully at: ${OUTPUT_DIR}/${FRAMEWORK_NAME}.xcframework"
echo "✅ Done!"