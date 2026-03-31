// swift-tools-version: 6.0
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "LongfellowZkp",
    platforms: [.macOS(.v14), .iOS(.v16), .watchOS(.v10)],
    products: [
        // Products define the executables and libraries a package produces, making them visible to other packages.
        .library(
            name: "LongfellowZkp",
            targets: ["LongfellowZkp"]
        ),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-certificates.git", from: "1.0.0"),
        .package(url: "https://github.com/niscy-eudiw/SwiftCBOR.git", from: "0.6.4"),
		.package(url: "https://github.com/eu-digital-identity-wallet/eudi-lib-ios-iso18013-data-model.git", from: "0.10.0"),
    ],
    targets: [
        // Targets are the basic building blocks of a package, defining a module or a test suite.
        // Targets can depend on other targets in this package and products from dependencies.
        .binaryTarget(name: "MdocZK", path: "./MdocZK.xcframework"),
        .target(
            name: "LongfellowZkp",
            dependencies: [
                .target(name: "MdocZK"),
                .product(name: "X509", package: "swift-certificates"),
                "SwiftCBOR",
                .product(name: "MdocDataModel18013", package: "eudi-lib-ios-iso18013-data-model"),
            ]
        ),
        .testTarget(
            name: "LongfellowZkpTests",
            dependencies: ["LongfellowZkp"],
            resources: [.process("Circuits")]
        ),
    ]
)
