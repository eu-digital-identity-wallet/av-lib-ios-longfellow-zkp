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
import MdocZK

/// Errors that can occur during ZK proof generation.
public enum ProofGenerationError: Error {
    /// The native prover returned a non-success error code.
	case generationFailed(errorCode: MdocProverErrorCode)
    /// The prover succeeded but returned an empty proof buffer.
    case emptyProof
}

/// Low-level bridge to the native Longfellow C prover and verifier functions.
public class LongfellowNatives {

    /// Returns a ``LongfellowZkSystemSpec`` for the given number of attributes.
    /// - Parameter numAttributes: The number of attributes the circuit should support.
    /// - Returns: A ``LongfellowZkSystemSpec`` instance.
    public static func getLongfellowZkSystemSpec(numAttributes: Int) -> LongfellowZkSystemSpec {
        return withUnsafePointer(to: kZkSpecs) { tuple in
            tuple.withMemoryRebound(to: ZkSpecStruct.self, capacity: Int(kNumZkSpecs)) { specs in
                for i in 0..<Int(kNumZkSpecs) {
                    let spec = specs[i]
                    if spec.num_attributes == numAttributes {
                        var hash = spec.circuit_hash
                        let circuitHash = withUnsafePointer(to: &hash) {
                            $0.withMemoryRebound(to: CChar.self, capacity: 65) {
                                String(cString: $0)
                            }
                        }
                        return LongfellowZkSystemSpec(
                            system: String(cString: spec.system),
                            circuitHash: circuitHash,
                            numAttributes: Int64(spec.num_attributes),
                            version: Int64(spec.version),
                            blockEncHash: Int64(spec.block_enc_hash),
                            blockEncSig: Int64(spec.block_enc_sig)
                        )
                    }
                }
                fatalError("No ZK spec found for \(numAttributes) attributes")
            }
        }
    }

    /// Generates circuit bytes for the given ZK system specification.
    /// - Parameter jzkSpec: The Longfellow ZK system specification.
    /// - Returns: The generated circuit data.
    public static func generateCircuit(jzkSpec: LongfellowZkSystemSpec) -> Data {
        let systemName = "longfellow-libzk-v1"
        var zkSpecStruct = ZkSpecStruct()
        systemName.withCString { cString in
            zkSpecStruct.system = UnsafePointer(cString)
        }
        withUnsafeMutablePointer(to: &zkSpecStruct) { zkSpecPtr in
            let circuitHashPtr = UnsafeMutableRawPointer(mutating: zkSpecPtr).advanced(by: MemoryLayout.offset(of: \ZkSpecStruct.circuit_hash)!)
            memset(circuitHashPtr, 0, 65)
            if let circuitHashData = jzkSpec.circuitHash.data(using: .utf8) {
                let len = min(circuitHashData.count, 64)
                circuitHashData.withUnsafeBytes { bytes in
                    if let baseAddress = bytes.baseAddress {
                        memcpy(circuitHashPtr, baseAddress, len)
                    }
                }
            }
        }
        zkSpecStruct.num_attributes = jzkSpec.numAttributes
        zkSpecStruct.version = jzkSpec.version
        zkSpecStruct.block_enc_hash = jzkSpec.blockEncHash
        zkSpecStruct.block_enc_sig = jzkSpec.blockEncSig
        var circuitPtr: UnsafeMutablePointer<UInt8>?
        var circuitLen: UInt = 0
        let rc = withUnsafeMutablePointer(to: &zkSpecStruct) { zkSpecPtr in
            generate_circuit(zkSpecPtr, &circuitPtr, &circuitLen)
        }
        guard rc == CIRCUIT_GENERATION_SUCCESS, let buffer = circuitPtr else {
            fatalError("Circuit generation failed with error code: \(rc.rawValue)")
        }
        let data = Data(bytes: buffer, count: Int(circuitLen))
        return data
    }

    /// Runs the native mdoc ZK prover to generate a proof.
    ///
    /// - Parameters:
    ///   - circuit: The circuit binary data.
    ///   - circuitSize: The size of the circuit data in bytes.
    ///   - mdoc: The CBOR-encoded `DeviceResponse` data.
    ///   - mdocSize: The size of the mdoc data in bytes.
    ///   - pkx: The hex-encoded x-coordinate of the issuer's EC public key.
    ///   - pky: The hex-encoded y-coordinate of the issuer's EC public key.
    ///   - transcript: The session transcript data.
    ///   - transcriptSize: The size of the transcript data in bytes.
    ///   - now: The current timestamp formatted as ISO 8601 (e.g. `"2023-11-02T09:00:00Z"`).
    ///   - zkSpec: The Longfellow ZK system specification.
    ///   - statements: The attributes to include in the proof.
    /// - Returns: The generated proof data.
    /// - Throws: ``ProofGenerationError`` if the native prover fails or returns an empty proof.
    public static func runMdocProver(circuit: Data, circuitSize: Int, mdoc: Data, mdocSize: Int, pkx: String, pky: String, transcript: Data, transcriptSize: Int, now: String, zkSpec: LongfellowZkSystemSpec, statements: [NativeAttribute]) throws -> Data {
        //print("// AV document\n// random: 32 bytes\n\nx:\n\(pkx)\n\ny:\n\(pky)\n\n\nsessionTranscript: (\(transcriptSize))\n\(transcript.toHexString())\n\n\nmdoc: (\(mdocSize))\n\(mdoc.toHexString())\n")
        // Allocate array for RequestedAttribute
        let requestedAttributes = UnsafeMutablePointer<RequestedAttribute>.allocate(capacity: statements.count)
        defer {  requestedAttributes.deallocate() }
        // Fill the requested attributes array
        for (index, statement) in statements.enumerated() {
            // let ra = requestedAttributes.advanced(by: index).pointee
            guard statement.namespace.count < 64 else {
                preconditionFailure("Namespace length must be less than 64")
            }
            guard statement.key.count < 32 else {
                preconditionFailure("Key length must be less than 32")
            }
            guard statement.value.count < 64 else {
                preconditionFailure("Value size must be less than 64")
            }
            // Copy namespace
            if let namespaceData = statement.namespace.data(using: .utf8) {
                namespaceData.withUnsafeBytes { (bytes: UnsafeRawBufferPointer) in
                    if let baseAddress = bytes.baseAddress {
                        memcpy(&requestedAttributes[index].namespace_id, baseAddress, namespaceData.count)
                    }
                }
                requestedAttributes[index].namespace_len = statement.namespace.count
            }
            // Copy key
            if let keyData = statement.key.data(using: .utf8) {
                keyData.withUnsafeBytes { (bytes: UnsafeRawBufferPointer) in
                    if let baseAddress = bytes.baseAddress {
                        memcpy(&requestedAttributes[index].id, baseAddress, keyData.count)
                    }
                }
                requestedAttributes[index].id_len = statement.key.count
            }
            // Copy value
            statement.value.withUnsafeBytes { (bytes: UnsafeRawBufferPointer) in
                if let baseAddress = bytes.baseAddress {
                    memcpy(&requestedAttributes[index].cbor_value, baseAddress, statement.value.count)
                }
            }
            requestedAttributes[index].cbor_value_len = statement.value.count
        }
        // Prepare system name
        let systemName = "longfellow-libzk-v1"
        // Create ZkSpecStruct
        var zkSpecStruct = ZkSpecStruct()
        systemName.withCString { cString in
            zkSpecStruct.system = UnsafePointer(cString)
        }
        // Zero out the circuit_hash buffer and copy the hash bytes
        withUnsafeMutablePointer(to: &zkSpecStruct) { zkSpecPtr in
            let circuitHashPtr = UnsafeMutableRawPointer(mutating: zkSpecPtr).advanced(by: MemoryLayout.offset(of: \ZkSpecStruct.circuit_hash)!)
            memset(circuitHashPtr, 0, 65)
            if let circuitHashData = zkSpec.circuitHash.data(using: .utf8) {
                let len = min(circuitHashData.count, 64)
                circuitHashData.withUnsafeBytes { (bytes: UnsafeRawBufferPointer) in
                    if let baseAddress = bytes.baseAddress {
                        memcpy(circuitHashPtr, baseAddress, len)
                    }
                }
            }
        }
        zkSpecStruct.num_attributes = zkSpec.numAttributes
        zkSpecStruct.version = zkSpec.version
        zkSpecStruct.block_enc_hash = zkSpec.blockEncHash
        zkSpecStruct.block_enc_sig = zkSpec.blockEncSig
        // Prepare output pointers
        var proofPtr: UnsafeMutablePointer<UInt8>?
        var proofLen: UInt = 0
        // Call the C function
        let rc = circuit.withUnsafeBytes { (circuitBytes: UnsafeRawBufferPointer) -> MdocProverErrorCode in
            guard let circuitBase = circuitBytes.baseAddress?.assumingMemoryBound(to: UInt8.self) else {
                return MDOC_PROVER_INVALID_INPUT
            }
            return mdoc.withUnsafeBytes { (mdocBytes: UnsafeRawBufferPointer) -> MdocProverErrorCode in
                guard let mdocBase = mdocBytes.baseAddress?.assumingMemoryBound(to: UInt8.self) else {
                    return MDOC_PROVER_INVALID_INPUT
                }
                return transcript.withUnsafeBytes { (transcriptBytes: UnsafeRawBufferPointer) -> MdocProverErrorCode in
                    guard let transcriptBase = transcriptBytes.baseAddress?.assumingMemoryBound(to: UInt8.self) else {
                        return MDOC_PROVER_INVALID_INPUT
                    }
                    return withUnsafeMutablePointer(to: &zkSpecStruct) { zkSpecPtr -> MdocProverErrorCode in
                        pkx.withCString { pkxCString in
                            pky.withCString { pkyCString in
                                now.withCString { nowCString in
                                    return run_mdoc_prover(
                                        circuitBase,
                                        circuitSize,
                                        mdocBase,
                                        mdocSize,
                                        pkxCString,
                                        pkyCString,
                                        transcriptBase,
                                        transcriptSize,
                                        requestedAttributes,
                                        statements.count,
                                        nowCString,
                                        &proofPtr,
                                        &proofLen,
                                        zkSpecPtr
                                    )
                                }
                            }
                        }
                    }
                }
            }
        }
        if rc == MDOC_PROVER_SUCCESS {
            guard let proofBuffer = proofPtr else {
                throw ProofGenerationError.emptyProof
            }
            let proof = Data(bytes: proofBuffer, count: Int(proofLen))
            // Note: Consider if we need to free proofPtr here
            return proof
        } else {
            throw ProofGenerationError.generationFailed(errorCode: rc)
        }
    }

    /// Runs the native mdoc ZK verifier to verify a proof.
    ///
    /// - Parameters:
    ///   - circuit: The circuit binary data.
    ///   - circuitSize: The size of the circuit data in bytes.
    ///   - pkx: The hex-encoded x-coordinate of the issuer's EC public key.
    ///   - pky: The hex-encoded y-coordinate of the issuer's EC public key.
    ///   - transcript: The session transcript data.
    ///   - transcriptSize: The size of the transcript data in bytes.
    ///   - now: The timestamp formatted as ISO 8601 (e.g. `"2023-11-02T09:00:00Z"`).
    ///   - proof: The proof data to verify.
    ///   - proofSize: The size of the proof data in bytes.
    ///   - docType: The document type string (e.g. `"org.iso.18013.5.1.mDL"`).
    ///   - zkSpec: The Longfellow ZK system specification.
    ///   - statements: The attributes that were claimed in the proof.
    /// - Returns: A `MdocVerifierErrorCode` indicating the verification result.
    public static func runMdocVerifier(circuit: Data, circuitSize: Int, pkx: String, pky: String, transcript: Data, transcriptSize: Int, now: String, proof: Data, proofSize: Int, docType: String, zkSpec: LongfellowZkSystemSpec, statements: [NativeAttribute]) -> MdocVerifierErrorCode {
        // Allocate array for RequestedAttribute
        let requestedAttributes = UnsafeMutablePointer<RequestedAttribute>.allocate(capacity: statements.count)
        defer {
            requestedAttributes.deallocate()
        }
        // Fill the requested attributes array
        for (index, statement) in statements.enumerated() {
            guard statement.namespace.count < 64 else {
                logger.warning("Namespace length must be less than 64")
                return MDOC_VERIFIER_INVALID_INPUT
            }
            guard statement.key.count < 32 else {
                logger.warning("Key length must be less than 32")
                return MDOC_VERIFIER_INVALID_INPUT
            }
            guard statement.value.count < 64 else {
                logger.warning("Value size must be less than 64")
                return MDOC_VERIFIER_INVALID_INPUT
            }
            // Copy namespace
            if let namespaceData = statement.namespace.data(using: .utf8) {
                namespaceData.withUnsafeBytes { (bytes: UnsafeRawBufferPointer) in
                    if let baseAddress = bytes.baseAddress {
                        memcpy(&requestedAttributes[index].namespace_id, baseAddress, namespaceData.count)
                    }
                }
                requestedAttributes[index].namespace_len = statement.namespace.count
            }
            // Copy key
            if let keyData = statement.key.data(using: .utf8) {
                keyData.withUnsafeBytes { (bytes: UnsafeRawBufferPointer) in
                    if let baseAddress = bytes.baseAddress {
                        memcpy(&requestedAttributes[index].id, baseAddress, keyData.count)
                    }
                }
                requestedAttributes[index].id_len = statement.key.count
            }
            // Copy value
            statement.value.withUnsafeBytes { (bytes: UnsafeRawBufferPointer) in
                if let baseAddress = bytes.baseAddress {
                    memcpy(&requestedAttributes[index].cbor_value, baseAddress, statement.value.count)
                }
            }
            requestedAttributes[index].cbor_value_len = statement.value.count
        }
        // Prepare system name
        let systemName = "longfellow-libzk-v1"
        // Create ZkSpecStruct
        var zkSpecStruct = ZkSpecStruct()
        systemName.withCString { cString in
            zkSpecStruct.system = UnsafePointer(cString)
        }
        // Zero out the circuit_hash buffer and copy the hash bytes
        withUnsafeMutablePointer(to: &zkSpecStruct) { zkSpecPtr in
            let circuitHashPtr = UnsafeMutableRawPointer(mutating: zkSpecPtr).advanced(by: MemoryLayout.offset(of: \ZkSpecStruct.circuit_hash)!)
            memset(circuitHashPtr, 0, 65)
            if let circuitHashData = zkSpec.circuitHash.data(using: .utf8) {
                let len = min(circuitHashData.count, 64)
                circuitHashData.withUnsafeBytes { (bytes: UnsafeRawBufferPointer) in
                    if let baseAddress = bytes.baseAddress {
                        memcpy(circuitHashPtr, baseAddress, len)
                    }
                }
            }
        }
        zkSpecStruct.num_attributes = zkSpec.numAttributes
        zkSpecStruct.version = zkSpec.version
        zkSpecStruct.block_enc_hash = zkSpec.blockEncHash
        zkSpecStruct.block_enc_sig = zkSpec.blockEncSig
        // Call the C function
        let result = circuit.withUnsafeBytes { (circuitBytes: UnsafeRawBufferPointer) -> MdocVerifierErrorCode in
            guard let circuitBase = circuitBytes.baseAddress?.assumingMemoryBound(to: UInt8.self) else {
				return MDOC_VERIFIER_INVALID_INPUT
            }
            return transcript.withUnsafeBytes { (transcriptBytes: UnsafeRawBufferPointer) -> MdocVerifierErrorCode in
                guard let transcriptBase = transcriptBytes.baseAddress?.assumingMemoryBound(to: UInt8.self) else {
                    return MDOC_VERIFIER_INVALID_INPUT
                }
                return proof.withUnsafeBytes { (proofBytes: UnsafeRawBufferPointer) -> MdocVerifierErrorCode in
                    guard let proofBase = proofBytes.baseAddress?.assumingMemoryBound(to: UInt8.self) else {
                        return MDOC_VERIFIER_INVALID_INPUT
                    }

                    return withUnsafeMutablePointer(to: &zkSpecStruct) { zkSpecPtr in
                        pkx.withCString { pkxCString in
                            pky.withCString { pkyCString in
                                now.withCString { nowCString in
                                    docType.withCString { docTypeCString in
                                        run_mdoc_verifier(
                                            circuitBase,
                                            circuitSize,
                                            pkxCString,
                                            pkyCString,
                                            transcriptBase,
                                            transcriptSize,
                                            requestedAttributes,
                                            statements.count,
                                            nowCString,
                                            proofBase,
                                            proof.count,
                                            docTypeCString,
                                            zkSpecPtr
                                        )
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        return result
    }
}

extension Data {

  var byteArray: Array<UInt8> {
    Array(self)
  }

  func toHexString() -> String {
    self.byteArray.toHexString()
  }
}

extension Array where Element == UInt8 {
public func toHexString() -> String {
    let res = `lazy`.reduce(into: "") {
      var s = String($1, radix: 16)
      if s.count == 1 {
        s = "0" + s
      }
      $0 += "0x\(s), "
    }
    return String(res.prefix(res.count-2))
  }
}
