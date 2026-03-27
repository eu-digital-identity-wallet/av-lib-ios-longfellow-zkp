# LongfellowZkp

A Swift library for zero-knowledge proof (ZKP) generation and verification of mdoc (mobile document) credentials using the Longfellow ZK system. Built on top of Google's `MdocZK` native library, it enables privacy-preserving selective disclosure of ISO/IEC 18013-5 mobile documents (e.g., mDL — mobile driving licence) and EU Digital Identity Wallet Age Verification credentials.

## Overview

LongfellowZkp provides a Swift-friendly interface to the native Longfellow ZK prover and verifier. It allows a **holder** to generate a zero-knowledge proof that certain attributes in their mdoc are valid (e.g., `age_over_18 == true`) without revealing the full document, and allows a **verifier** to confirm the proof.

### Key Features

- **Proof generation** — produce ZK proofs from mdoc `DeviceResponse` CBOR data
- **Proof verification** — verify proofs against issuer public keys and session transcripts
- **Circuit management** — load and match circuit files by version, attribute count, and hash
- **EC key extraction** — extract P-256/P-384/P-521 public keys from X.509 issuer certificates
- **ZK system spec negotiation** — parse and match `ZkSystemSpec` from DCQL JSON requests

## Requirements

| Requirement | Version |
|---|---|
| Swift | 6.0+ |
| iOS | 16.0+ |

## Installation

### Swift Package Manager

Add the dependency to your `Package.swift`:

```swift
dependencies: [
    .package(url: "https://github.com/eu-digital-identity-wallet/av-lib-ios-longfellow-zkp.git", from: "0.1.0"),
]
```

Then add `LongfellowZkp` to your target's dependencies:

```swift
.target(
    name: "YourTarget",
    dependencies: [
        .product(name: "LongfellowZkp", package: "av-lib-ios-longfellow-zkp"),
    ]
),
```

## Architecture

The library is composed of two modules:

### `LongfellowZkp`

The main module containing the ZKP logic:

| Type | Description |
|---|---|
| `LongfellowZkSystem` | Core struct implementing `ZkSystemProtocol`. Manages circuits and performs proof generation/verification. |
| `LongfellowZkSystemSpec` | Describes a ZK specification: system name, circuit hash, version, number of attributes, and block encoding parameters. |
| `CircuitEntry` | Represents a loaded circuit file with its parsed spec and URL reference. |
| `LongfellowNatives` | Low-level bridge to the native C prover/verifier functions in `MdocZK`. |
| `NativeAttribute` | A namespace/key/value triple representing a single mdoc attribute for proof operations. |

### `MdocZkp`

Supporting utilities:

| Type | Description |
|---|---|
| `ECKeyExtractor` | Extracts EC public keys (P-256, P-384, P-521) from DER-encoded X.509 certificates. |
| `ProofVerificationFailureException` | Error thrown when proof verification fails. |

### `MdocZK` (XCFramework)

The pre-built native C library providing the Longfellow ZK prover, verifier, and circuit generation functions.

## Usage

### 1. Loading Circuits

Circuit files follow the naming convention: `<version>_<numAttributes>_<blockEncHash>_<blockEncSig>_<circuitHash>`

Example filename: `6_1_4096_2945_137e5a75ce72735a37c8a72da1a8a0a5df8d13365c2ae3d2c2bd6a0e7197c7c6`

**From the app bundle:**

```swift
import LongfellowZkp

// Automatically enumerate circuit files from the app bundle
let circuits = LongfellowZkSystem.enumerateLongfellowCircuits()
let zkSystem = LongfellowZkSystem(circuits: circuits)
```

**From a specific URL:**

```swift
let filename = "6_1_4096_2945_137e5a75ce72735a37c8a72da1a8a0a5df8d13365c2ae3d2c2bd6a0e7197c7c6"
let circuitURL = Bundle.main.url(forResource: filename, withExtension: nil)!
let circuit = try CircuitEntry(circuitFilename: filename, circuitUrl: circuitURL)
let zkSystem = LongfellowZkSystem(circuits: [circuit])
```

### 2. Matching a ZkSystemSpec from a DCQL Request

When a verifier sends a list of supported ZK system specs, find the best match:

```swift
// Parse specs from a DCQL JSON response
let jsonString = """
{
    "zk_system_type": [
        {
            "system": "longfellow-libzk-v1",
            "circuit_hash": "f88a39e561ec...",
            "num_attributes": 1,
            "version": 5,
            "block_enc_hash": 4096,
            "block_enc_sig": 2945
        }
    ]
}
"""
let zkLongfellowSpecs = try LongfellowZkSystemSpec.parseFromJSONString(jsonString)

// Find a matching local circuit
let matchedSpec = zkSystem.getMatchingSystemSpec(
    zkSystemSpecs: zkLongfellowSpecs.map(\.zkSystemSpec),
    numAttributesRequested: 1
)
```

### 3. Generating a ZK Proof

```swift
import SwiftCBOR
import MdocDataModel18013

// Build the ZkSystemSpec (typically received from a verifier's DCQL request)
let zkSpec = ZkSystemSpec(
    id: "longfellow-libzk-v1_<circuitHash>",
    system: "longfellow-libzk-v1",
    params: longfellowSpec.toZkParams()
)

// Generate proof from a Document
let zkDocument = try zkSystem.generateProof(
    zkSystemSpec: zkSpec,
    document: document,
    sessionTranscriptBytes: sessionTranscript,
    timestamp: Date()
)

// Or generate proof from raw DeviceResponse bytes
let zkDocument = try zkSystem.generateProof(
    zkSystemSpec: spec,
    docBytes: deviceResponseBytes,
    x: issuerPublicKeyX,   // hex-encoded, e.g. "0x6789e9..."
    y: issuerPublicKeyY,   // hex-encoded
    sessionTranscriptBytes: sessionTranscript,
    timestamp: Date()
)
```

### 4. Verifying a ZK Proof

```swift
try zkSystem.verifyProof(
    zkDocument: zkDocument,
    zkSystemSpec: spec,
    sessionTranscriptBytes: sessionTranscript
)
// If no error is thrown, verification succeeded.
```

### Integration with Wallet Kit

Once configured, Eudi [WalletKit](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-wallet-kit) will automatically generate zero-knowledge proofs for ZK-enabled requests in both proximity (ISO 18013-5) and OpenID4VP use cases. You only need the following source code to generate proofs, provided that you include the required circuits in the app bundle. 

```swift
let circuits = LongfellowZkSystem.enumerateLongfellowCircuits(bundle: Bundle.main)
if !circuits.isEmpty {
    wallet.zkSystemRepository = ZkSystemRepository(systems: [LongfellowZkSystem(circuits: circuits)])
}
```

You need also to include the circuits in your bundle. You can find them in the [multipaz repository](https://github.com/openwallet-foundation/multipaz) in the folder `samples/testapp/src/commonMain/composeResources/files/longfellow-libzk-v1`

### 5. Extracting Issuer Public Key

```swift
let (x, y) = try LongfellowZkSystem.getPublicKeyFromIssuerCert(document: document)
// x and y are hex-encoded strings prefixed with "0x"
```

## Circuit File Format

Circuit filenames encode their parameters:

```
<version>_<numAttributes>_<blockEncHash>_<blockEncSig>_<circuitHash>
```

| Component | Description |
|---|---|
| `version` | ZK specification version number |
| `numAttributes` | Number of attributes the circuit supports |
| `blockEncHash` | Block encoding parameter for hash |
| `blockEncSig` | Block encoding parameter for signature |
| `circuitHash` | SHA-256 hash identifying the circuit |

## Building the MdocZK XCFramework

The `MdocZK.xcframework` bundles the native Longfellow static libraries for iOS device and simulator architectures. Use the provided script to rebuild it from pre-compiled static libraries.

### Prerequisites

The pre-compiled native static libraries can be obtained from the [Multipaz](https://github.com/openwallet-foundation/multipaz) repository at the folder `multipaz-longfellow/src/iosMain/nativeLibs`. Copy the architecture-specific folders into the same directory as this [script](https://github.com/niscy-eudiw/longfellow-zk/blob/main/scripts/multipaz_build_xcframework.sh) file.
The output will be at `output/MdocZK.xcframework`.

Alternatively, you can build the native static libraries from our forked Longfellow C [codebase](https://github.com/niscy-eudiw/longfellow-zk), and the build [script](https://github.com/niscy-eudiw/longfellow-zk/blob/main/scripts/build_xcframework.sh) file.

## Dependencies

| Package | Purpose |
|---|---|
| [swift-certificates](https://github.com/apple/swift-certificates) (X509) | X.509 certificate parsing for EC key extraction |
| [SwiftCBOR](https://github.com/niscy-eudiw/SwiftCBOR) | CBOR encoding/decoding for mdoc data |
| [eudi-lib-ios-iso18013-data-model](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-iso18013-data-model) | ISO 18013-5 data model types (`Document`, `DeviceResponse`, `IssuerSigned`, `ZkSystemSpec`, etc.) |

## Testing

```bash
swift test
```

Tests are located in `Tests/av-lib-ios-longfellow-zkpTests/` and include:
- ZK system spec parsing from DCQL JSON
- Issuer public key extraction
- Full proof generation flow (prover + verifier)
- Document CBOR round-trip encoding

### Disclaimer
The released software is a initial development release version: 
-  The initial development release is an early endeavor reflecting the efforts of a short timeboxed period, and by no means can be considered as the final product.  
-  The initial development release may be changed substantially over time, might introduce new features but also may change or remove existing ones, potentially breaking compatibility with your existing code.
-  The initial development release is limited in functional scope.
-  The initial development release may contain errors or design flaws and other problems that could cause system or other failures and data loss.
-  The initial development release has reduced security, privacy, availability, and reliability standards relative to future releases. This could make the software slower, less reliable, or more vulnerable to attacks than mature software.
-  The initial development release is not yet comprehensively documented. 
-  Users of the software must perform sufficient engineering and additional testing in order to properly evaluate their application and determine whether any of the open-sourced components is suitable for use in that application.
-  We strongly recommend to not put this version of the software into production use.
-  Only the latest version of the software will be supported

### License details

Copyright (c) 2023 European Commission

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
