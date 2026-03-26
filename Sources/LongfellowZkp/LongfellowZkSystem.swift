/*
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
*/

import Foundation
import SwiftCBOR
import MdocZK
import MdocDataModel18013
import os.log

// MARK: - LongfellowZkSystem

/// Abstract base class for Longfellow-based ZK systems implementing `ZkSystem`.
///
/// Provides core logic for proof generation and verification using native Longfellow
/// libraries. Circuit files are expected to be named with the format:
/// `<version>_<numAttributes>_<blockEncHash>_<blockEncSig>_<circuitHash>`.
public struct LongfellowZkSystem: ZkSystemProtocol {
    private let circuits: [CircuitEntry]
    static let longFellowSystemName = "longfellow-libzk-v1"
 
    private static let TAG = "LongfellowZkSystem"

    /// Enumerates filenames and file URLs in the longfellow-libzk-v1 folder in the app bundle.
    /// - Returns: Array of (filename, fileURL) tuples for each file in the folder.
    public static func enumerateLongfellowCircuits(bundle: Bundle = Bundle.main) -> [CircuitEntry] {
        guard let folderURL = bundle.resourceURL else {
            logger.warning("Resources not found in bundle.")
            return []
        }
        do {
            let fileURLs = try FileManager.default.contentsOfDirectory(at: folderURL, includingPropertiesForKeys: nil, options: [.skipsHiddenFiles]).filter { $0.pathExtension.isEmpty }
            return fileURLs
                .map { ($0.lastPathComponent, $0) }
                .compactMap { try? CircuitEntry(circuitFilename: $0, circuitUrl: $1)}
        } catch {
            logger.warning("Failed to enumerate files in longfellow-libzk-v1: \(error.localizedDescription)")
            return []
        }
    }

    /// The list of ``ZkSystemSpec`` entries derived from the loaded circuits.
    public var systemSpecs: [ZkSystemSpec] {
        return circuits.map { $0.zkSystemSpec }
    }

    /// The ZK system name identifier (`"longfellow-libzk-v1"`).
    public var name: String { Self.longFellowSystemName }

    /// Creates a new `LongfellowZkSystem` with the given circuit entries.
    /// - Parameter circuits: The circuit entries to register. Defaults to an empty array.
    public init(circuits: [CircuitEntry] = []) {
        self.circuits = circuits
    }

    // MARK: - Private Helper Methods

    /// Formats raw coordinate bytes as a hex string prefixed with `"0x"`.
    /// - Parameter value: The raw bytes of the EC coordinate.
    /// - Returns: A hex-encoded string representation (e.g. `"0x6789e9..."`).
    public static func getFormattedCoordinate(value: Data) -> String { "0x" + value.map { String(format: "%02x", $0) }.joined() }

    private func formatDate(timestamp: Date) -> String {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        var dateString = formatter.string(from: timestamp)
        // Truncate to whole seconds
        if let dotIndex = dateString.firstIndex(of: ".") {
            //let endIndex = dateString.index(dotIndex, offsetBy: 1)
            dateString = String(dateString[..<dotIndex]) + "Z"
        }
        return dateString
    }

    private func getLongfellowCircuitEntry(zkSystemSpec: ZkSystemSpec) -> CircuitEntry? {
        let entry = circuits.first { circuitEntry in
            let circuitSpec = circuitEntry.zkSystemSpec

            let chash: String? = circuitSpec.params["circuit_hash"]?.stringValue
            let cversion = circuitSpec.params["version"]?.intValue
            let cnumattr = circuitSpec.params["num_attributes"]?.intValue
            let zkhash = zkSystemSpec.params["circuit_hash"]?.stringValue
            let zkversion = zkSystemSpec.params["version"]?.intValue
            let zknumattr = zkSystemSpec.params["num_attributes"]?.intValue
            return chash == zkhash && cversion ==  zkversion && cnumattr == zknumattr
        }

        return entry
    }

    private func getLongfellowZkSystemSpec(zkSystemSpec: ZkSystemSpec) -> LongfellowZkSystemSpec? {
        return getLongfellowCircuitEntry(zkSystemSpec: zkSystemSpec)?.longfellowZkSystemSpec
    }

    private func getCircuitBytes(zkSystemSpec: ZkSystemSpec) throws -> Data? {
        return try getLongfellowCircuitEntry(zkSystemSpec: zkSystemSpec)?.getCircuitBytes()
    }

    static func parseCircuitFilename(_ circuitFileName: String) throws -> (ZkSystemSpec, LongfellowZkSystemSpec) {
        guard !circuitFileName.contains("/") else {
            throw NSError(domain: "LongfellowZkSystem", code: 4, userInfo: [NSLocalizedDescriptionKey: "circuitFilename must not include any directory separator"])
        }
        let circuitNameParts = circuitFileName.split(separator: "_").map(String.init)
        guard circuitNameParts.count == 5 else {
            throw NSError(domain: "LongfellowZkSystem", code: 1, userInfo: [NSLocalizedDescriptionKey: "\(circuitFileName) does not match expected <version>_ <numAttributes>_ <blockEncHash>_ <blockEncSig>_ <hash>"])
        }
        guard let version = Int64(circuitNameParts[0]) else {
            throw NSError(domain: "LongfellowZkSystem", code: 1, userInfo: [NSLocalizedDescriptionKey: "\(circuitFileName) does not match expected format, could not find version number."])
        }
        guard let numAttributes = Int64(circuitNameParts[1]) else {
            throw NSError(domain: "LongfellowZkSystem", code: 1, userInfo: [NSLocalizedDescriptionKey: "\(circuitFileName) does not match expected format, could not find number of attributes."])
        }
        guard let blockEncHash = Int64(circuitNameParts[2]) else {
            throw NSError(domain: "LongfellowZkSystem", code: 1, userInfo: [NSLocalizedDescriptionKey: "\(circuitFileName) does not match expected format, could not find blockEncHash."])
        }
        guard let blockEncSig = Int64(circuitNameParts[3]) else {
            throw NSError(domain: "LongfellowZkSystem", code: 1, userInfo: [NSLocalizedDescriptionKey: "\(circuitFileName) does not match expected format, could not find blockEncSig."])
        }
        let circuitHash = circuitNameParts[4]
        let longfellowSpec = LongfellowZkSystemSpec(
            system: Self.longFellowSystemName, circuitHash: circuitHash, numAttributes: numAttributes, version: version, blockEncHash: blockEncHash, blockEncSig: blockEncSig)
        let spec = ZkSystemSpec(id: "\(Self.longFellowSystemName)_\(circuitFileName)", system: Self.longFellowSystemName, params: longfellowSpec.toZkParams())
        return (spec, longfellowSpec)
    }

    /// Extracts the issuer's EC public key coordinates from the first certificate in the document's X5Chain.
    /// - Parameter document: The mdoc `Document` containing issuer-signed data.
    /// - Returns: A tuple of hex-encoded `x` and `y` coordinates prefixed with `"0x"`.
    /// - Throws: An error if the certificate cannot be parsed or does not contain a valid EC key.
    public static func getPublicKeyFromIssuerCert(document: Document) throws -> (x: String, y: String) {
        let issuerCert = document.issuerSigned.issuerAuth.x5chain.first!
        let publicKeyInfo = try ECKeyExtractor.extractECCKeyInfo(from: Data(issuerCert))
        let publicKeyRawData = publicKeyInfo.x963KeyData.dropFirst()
        let x = Self.getFormattedCoordinate(value: publicKeyRawData.prefix(publicKeyRawData.count / 2))
        let y = Self.getFormattedCoordinate(value: publicKeyRawData.suffix(publicKeyRawData.count / 2))
        return (x, y)
    }
    // MARK: - ZkSystem Protocol Methods

    /// Generates a zero-knowledge proof for a given document.
    ///
    /// Wraps the document in a `DeviceResponse` CBOR structure and delegates to the raw-bytes overload.
    /// The issuer public key is automatically extracted from the document's X5Chain.
    ///
    /// - Parameters:
    ///   - zkSystemSpec: The ZK system specification identifying the circuit to use.
    ///   - document: The mdoc `Document` to generate a proof for.
    ///   - sessionTranscriptBytes: The session transcript bytes for the presentation.
    ///   - timestamp: The current time (fractional seconds are truncated).
    /// - Returns: A ``ZkDocument`` containing the proof and associated document data.
    /// - Throws: An error if the circuit is not found or proof generation fails.
    public func generateProof(zkSystemSpec: ZkSystemSpec, document: Document, sessionTranscriptBytes: [UInt8], timestamp: Date) throws -> ZkDocument {
        // The Longfellow ZKP library expects `DeviceResponse` CBOR, and will grab the 1st document in the array.
        let longfellowDocBytes = CBOR.encode(CBOR.map([
            CBOR.utf8String("version"): CBOR.utf8String("1.0"),
            CBOR.utf8String("documents"): CBOR.array([document.toCBOR(options: CBOROptions())]),
            CBOR.utf8String("status"): CBOR.unsignedInt(0)
        ]), options: CBOROptions())
        let (x, y) = try Self.getPublicKeyFromIssuerCert(document: document)
        return try generateProof(zkSystemSpec: zkSystemSpec, docBytes: longfellowDocBytes, x: x, y: y, sessionTranscriptBytes: sessionTranscriptBytes, timestamp: timestamp)
    }

    /// Generates a zero-knowledge proof from raw `DeviceResponse` CBOR bytes.
    ///
    /// - Parameters:
    ///   - zkSystemSpec: The ZK system specification identifying the circuit to use.
    ///   - docBytes: The CBOR-encoded `DeviceResponse` bytes.
    ///   - x: The hex-encoded x-coordinate of the issuer's public key, or `nil` to extract from the document.
    ///   - y: The hex-encoded y-coordinate of the issuer's public key, or `nil` to extract from the document.
    ///   - sessionTranscriptBytes: The session transcript bytes for the presentation.
    ///   - timestamp: The current time (fractional seconds are truncated).
    /// - Returns: A ``ZkDocument`` containing the proof and associated document data.
    /// - Throws: An error if the circuit is not found, the document is invalid, or proof generation fails.
    public func generateProof(zkSystemSpec: ZkSystemSpec, docBytes: [UInt8], x: String?, y: String?, sessionTranscriptBytes: [UInt8], timestamp: Date) throws -> ZkDocument {
        guard let longfellowZkSystemSpec = getLongfellowZkSystemSpec(zkSystemSpec: zkSystemSpec) else { throw NSError(domain: "LongfellowZkSystem", code: 1, userInfo: [NSLocalizedDescriptionKey: "Circuit not found for system spec: \(zkSystemSpec)"]) }
        guard let circuitBytes = try getCircuitBytes(zkSystemSpec: zkSystemSpec) else { throw NSError(domain: "LongfellowZkSystem", code: 1, userInfo: [NSLocalizedDescriptionKey: "Circuit not found for system spec: \(zkSystemSpec)"]) }
        let dr = try DeviceResponse(data: docBytes)
        guard let document = dr.documents?.first else { throw NSError(domain: "LongfellowZkSystem", code: 2, userInfo: [NSLocalizedDescriptionKey: "No document found in DeviceResponse"]) }
        let docType = document.docType
        let issuerCert = document.issuerSigned.issuerAuth.x5chain.first!
        var attributes: [NativeAttribute] = []
        var issuerSigned: [String: [String: CBOR]] = [:]
        for (namespaceName, issuerSignedItems) in document.issuerSigned.issuerNameSpaces?.nameSpaces ?? [:] {
            var values: [String: CBOR] = [:]
            for issuerSignedItem in issuerSignedItems {
                values[issuerSignedItem.elementIdentifier] = issuerSignedItem.elementValue
                let attr = NativeAttribute(namespace: namespaceName, key: issuerSignedItem.elementIdentifier, value: Data(CBOR.encode(issuerSignedItem.elementValue)))
                attributes.append(attr)
            }
            issuerSigned[namespaceName] = values
        }
        // According to Longfellow-ZK spec, can't have any fractional seconds.
        let adjustedTimestamp = timestamp.truncateToWholeSeconds()
        let (xi, yi) = if x == nil || y == nil { try Self.getPublicKeyFromIssuerCert(document: document)} else { ("", "")}
        let proof = try LongfellowNatives.runMdocProver(
            circuit: circuitBytes,
            circuitSize: circuitBytes.count,
            mdoc: Data(docBytes),
            mdocSize: docBytes.count,
            pkx: x ?? xi,
            pky: y ?? yi,
            transcript: Data(sessionTranscriptBytes),
            transcriptSize: sessionTranscriptBytes.count,
            now: formatDate(timestamp: adjustedTimestamp),
            zkSpec: longfellowZkSystemSpec,
            statements: attributes
        )
        let zkDocument = ZkDocument(
            documentData: ZkDocumentData(
                zkSystemSpecId: zkSystemSpec.id,
                docType: docType,
                timestamp: adjustedTimestamp,
                issuerSigned: issuerSigned,
                deviceSigned: [:],     // TODO: support deviceSigned in Longfellow
                msoX5chain: [issuerCert]
            ), proof: proof,
        )
        return zkDocument
    }

    /// Verifies a zero-knowledge proof contained in a ``ZkDocument``.
    ///
    /// Extracts the issuer public key from the document's X5Chain and runs the native verifier.
    ///
    /// - Parameters:
    ///   - zkDocument: The ``ZkDocument`` containing the proof and document data to verify.
    ///   - zkSystemSpec: The ZK system specification identifying the circuit.
    ///   - sessionTranscriptBytes: The session transcript bytes used during proof generation.
    /// - Throws: ``ProofVerificationFailureException`` if verification fails, or an `NSError` if inputs are invalid.
    public func verifyProof(zkDocument: ZkDocument, zkSystemSpec: ZkSystemSpec, sessionTranscriptBytes: [UInt8]) throws {
        guard let msoX5chain = zkDocument.documentData.msoX5chain,  !msoX5chain.isEmpty else {
            throw NSError(domain: "LongfellowZkSystem", code: 3, userInfo: [NSLocalizedDescriptionKey: "zkDocument must contain at least 1 certificate in msoX5chain."])
        }
        let issuerCert = msoX5chain[0]
        let publicKeyInfo = try ECKeyExtractor.extractECCKeyInfo(from: Data(issuerCert))
        let x = Self.getFormattedCoordinate(value: publicKeyInfo.x963KeyData.prefix(publicKeyInfo.x963KeyData.count / 2))
        let y = Self.getFormattedCoordinate(value: publicKeyInfo.x963KeyData.suffix(publicKeyInfo.x963KeyData.count / 2))
        guard let longfellowZkSystemSpec = getLongfellowZkSystemSpec(zkSystemSpec: zkSystemSpec) else {
            throw NSError(domain: "LongfellowZkSystem", code: 1,
                         userInfo: [NSLocalizedDescriptionKey: "Circuit not found for system spec: \(zkSystemSpec)"])
        }
        guard let circuitBytes = try getCircuitBytes(zkSystemSpec: zkSystemSpec) else {
            throw NSError(domain: "LongfellowZkSystem", code: 1,
                         userInfo: [NSLocalizedDescriptionKey: "Circuit not found for system spec: \(zkSystemSpec)"])
        }
        var attributes: [NativeAttribute] = []
        for (nameSpaceName, dataElements) in zkDocument.documentData.issuerSigned {
            for (dataElementName, dataElementValue) in dataElements {
                attributes.append(NativeAttribute(
                    namespace: nameSpaceName,
                    key: dataElementName,
                    value: Data(dataElementValue.encode())
                ))
            }
        }
        let verifierResult = LongfellowNatives.runMdocVerifier(
            circuit: circuitBytes,
            circuitSize: circuitBytes.count,
            pkx: x,
            pky: y,
            transcript: Data(sessionTranscriptBytes),
            transcriptSize: sessionTranscriptBytes.count,
            now: formatDate(timestamp: zkDocument.documentData.timestamp),
            proof: zkDocument.proof,
            proofSize: zkDocument.proof.count,
            docType: zkDocument.documentData.docType,
            zkSpec: longfellowZkSystemSpec,
            statements: attributes
        )
        logger.info("Verification Code: \(verifierResult.rawValue)")

        if verifierResult != MDOC_VERIFIER_SUCCESS {
            throw ProofVerificationFailureException(message: "Verification failed with error: \(verifierResult.rawValue)")
        }
    }

    /// Longfellow encodes a version number, the number of attributes, and the circuit
    /// hash in the filename with the circuit data so in addition to `circuitBytes`, pass this
    /// information in `circuitFilename` encoded in the following way:
    /// `<version>_<numAttributes>_<blockEncHash>_<blockEncSig>_<circuitHash>`.
    /// circuitFilename should be only the name of the file, and must not include any path separators.
    ///

    /// Finds the best matching `ZkSystemSpec` from a given list based on the number of signed attributes.
    ///
    /// - Parameters:
    ///   - zkSystemSpecs: the available specs from the request
    ///   - requestedClaims: the request to fulfill
    /// - Returns: the best matching `ZkSystemSpec`, or nil if none are suitable
    public func getMatchingSystemSpec(zkSystemSpecs: [ZkSystemSpec], numAttributesRequested: Int64) -> ZkSystemSpec? {
        guard numAttributesRequested > 0 else {
            return nil
        }
        // Get the set of allowed circuit hashes from the input list for efficient lookup.
        let allowedCircuitHashes = Set(
            zkSystemSpecs.compactMap { $0.params["circuit_hash"]?.stringValue }
        )
        // If no valid hashes are provided from the input list, we cannot find a match.
        guard !allowedCircuitHashes.isEmpty else {
            return nil
        }
        return systemSpecs
            .filter { spec in
                guard let circuitHash = spec.params["circuit_hash"]?.stringValue,
                      allowedCircuitHashes.contains(circuitHash),
                      let numAttributes = spec.params["num_attributes"]?.intValue,
                      numAttributes == numAttributesRequested else {
                    return false
                }
                return true
            }
            .sorted { spec1, spec2 in
                let version1 = spec1.params["version"]?.intValue ?? Int64.min
                let version2 = spec2.params["version"]?.intValue ?? Int64.min
                return version1 < version2
            }
            .first
    }
}
// MARK: - CircuitEntry


// MARK: - Date Extension

private extension Date {
    func truncateToWholeSeconds() -> Date {
        return Date(timeIntervalSince1970: floor(self.timeIntervalSince1970))
    }
}
