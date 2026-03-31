# LongfellowZkp

A Swift library for zero-knowledge proof (ZKP) generation and verification of mdoc (mobile document) credentials using the Longfellow ZK system. Built on top of Google's `MdocZK` native library, it enables privacy-preserving selective disclosure of ISO/IEC 18013-5 mobile documents (e.g., mDL — mobile driving licence) and EU Digital Identity Wallet Age Verification credentials.

## Overview

LongfellowZkp provides a Swift-friendly interface to the native Longfellow ZK prover and verifier. It allows a **holder** to generate a zero-knowledge proof that certain attributes in their mdoc are valid (e.g., `age_over_18 == true`) without revealing the full document, and allows a **verifier** to confirm the proof.

### Key Features

- **Proof generation** — produce ZK proofs from mdoc `DeviceResponse` CBOR data
- **Proof verification** — verify proofs against issuer public keys and session transcripts
- **Circuit management** — load and match circuit files by version, attribute count, and hash
- **ZK system spec lookup** — retrieve built-in ZK specs by number of attributes from the native library
- **Circuit generation** — dynamically generate circuit binary data at runtime from a ZK system spec
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
| `LongfellowNatives` | Low-level bridge to the native C prover/verifier functions in `MdocZK`. Also provides ZK system spec lookup and circuit generation. |
| `NativeAttribute` | A namespace/key/value triple representing a single mdoc attribute for proof operations. |


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

### 2. Retrieving a ZK System Spec

Use `LongfellowNatives.getLongfellowZkSystemSpec` to look up the built-in ZK system specification for a given number of attributes. This queries the native `MdocZK` library's embedded spec table:

```swift
let spec = LongfellowNatives.getLongfellowZkSystemSpec(numAttributes: 1)
// spec.system        → "longfellow-libzk-v1"
// spec.circuitHash   → "137e5a75ce72..."
// spec.version       → 6
// spec.numAttributes → 1
// spec.blockEncHash  → 4096
// spec.blockEncSig   → 2945
```

### 3. Generating a Circuit

Use `LongfellowNatives.generateCircuit` to generate the circuit binary data from a `LongfellowZkSystemSpec`. This calls the native `generate_circuit` function:

```swift
let spec = LongfellowNatives.getLongfellowZkSystemSpec(numAttributes: 1)
let circuitData = LongfellowNatives.generateCircuit(jzkSpec: spec)
// circuitData contains the binary circuit that can be used for proof generation/verification
```

This is useful when you need to generate circuits dynamically at runtime rather than bundling pre-built circuit files.

### 4. Matching a ZkSystemSpec from a DCQL Request

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

### 5. Generating a ZK Proof

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

### 6. Verifying a ZK Proof

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

### 7. Extracting Issuer Public Key

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

You can build the native static libraries from our forked Longfellow C [codebase](https://github.com/niscy-eudiw/longfellow-zk), and the build [script](https://github.com/niscy-eudiw/longfellow-zk/blob/main/scripts/build_xcframework.sh) file.

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

**ZKP Proof Calculation via Silent Push — Summary**

The DC API Document Provider extension process cannot currently perform zero-knowledge proof (ZKP) due to memory constraints. However, this work can by done by the main app process, which has more available memory.

The two processes communicate through shared storage. When the extension needs a ZKP computed, it writes request data to shared storage and sends a [silent push notification](https://developer.apple.com/documentation/usernotifications/pushing-background-updates-to-your-app) to wake the main app in the background. Silent push notifications are remote notifications with only the `content-available: 1` flag — they don't display alerts or play sounds, but wake the app and give it up to 30 seconds to perform work. 

Once woken, the main app reads the request, performs the ZKP computation using bundled cryptographic circuit files, and writes the result back to shared storage. The extension polls for the result on a short interval.

In the rare case the silent push doesn't arrive or the main app doesn't produce a result in time, the extension can fall back to generating a response without a ZKP.


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
