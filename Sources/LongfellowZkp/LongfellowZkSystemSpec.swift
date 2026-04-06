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
import MdocDataModel18013
/// - Properties:
///   - system: the ZK system name.
///   - circuitHash: the hash of the circuit.
///   - numAttributes: the number of attributes that the circuit supports.
///   - version: the version of the ZK spec.
///   - blockEncHash: block encoding hash parameter
///   - blockEncSig: block encoding signature parameter
public struct LongfellowZkSystemSpec: Sendable, Identifiable, Codable {
    public var id: String { system }
    let system: String
    let circuitHash: String
    let numAttributes: Int
    let version: Int
    let blockEncHash: Int
    let blockEncSig: Int
    
    enum CodingKeys: String, CodingKey {
        case system
        case circuitHash = "circuit_hash"
        case numAttributes = "num_attributes"
        case version
        case blockEncHash = "block_enc_hash"
        case blockEncSig = "block_enc_sig"
    }
    
    /// Creates a new `LongfellowZkSystemSpec`.
    /// - Parameters:
    ///   - system: The ZK system name (e.g. `"longfellow-libzk-v1"`).
    ///   - circuitHash: The SHA-256 hash identifying the circuit.
    ///   - numAttributes: The number of attributes the circuit supports.
    ///   - version: The ZK specification version.
    ///   - blockEncHash: The block encoding parameter for hash.
    ///   - blockEncSig: The block encoding parameter for signature.
    public init(system: String, circuitHash: String, numAttributes: Int64, version: Int64, blockEncHash: Int64, blockEncSig: Int64) {
        self.system = system
        self.circuitHash = circuitHash
        self.numAttributes = Int(numAttributes)
        self.version = Int(version)
        self.blockEncHash = Int(blockEncHash)
        self.blockEncSig = Int(blockEncSig)
    }
}

// MARK: - ZkParams Conversion
extension LongfellowZkSystemSpec {
    /// Converts this spec to a `ZkParams` ordered dictionary.
    public func toZkParams() -> ZkParams {
        ZkParams(
            uniqueKeysWithValues: [
                ("version", ZkParam.intParam(Int64(version))),
                ("circuit_hash", ZkParam.stringParam(circuitHash)),
                ("num_attributes", ZkParam.intParam(Int64(numAttributes))),
                ("block_enc_hash", ZkParam.intParam(Int64(blockEncHash))),
                ("block_enc_sig", ZkParam.intParam(Int64(blockEncSig)))
            ]
        )
    }

    public var zkSystemSpec: ZkSystemSpec {
        ZkSystemSpec(zkSystemId: id, system: system, params: toZkParams())
    }
}

// MARK: - JSON Parsing
extension LongfellowZkSystemSpec {
    /// Parse ZK system specs from JSON data
    /// - Parameter jsonData: The JSON data containing the zk_system_type array
    /// - Returns: Array of LongfellowZkSystemSpec objects
    /// - Throws: DecodingError if the JSON is malformed
    public static func parseFromJSON(_ jsonData: Data) throws -> [LongfellowZkSystemSpec] {
        struct ZKSystemResponse: Codable {
            let zkSystemType: [LongfellowZkSystemSpec]
            
            enum CodingKeys: String, CodingKey {
                case zkSystemType = "zk_system_type"
            }
        }
        
        let response = try JSONDecoder().decode(ZKSystemResponse.self, from: jsonData)
        return response.zkSystemType
    }
    
    /// Parse ZK system specs from JSON string
    /// - Parameter jsonString: The JSON string containing the zk_system_type array
    /// - Returns: Array of LongfellowZkSystemSpec objects
    /// - Throws: DecodingError if the JSON is malformed
    public static func parseFromJSONString(_ jsonString: String) throws -> [LongfellowZkSystemSpec] {
        guard let data = jsonString.data(using: .utf8) else {
            throw DecodingError.dataCorrupted(
                DecodingError.Context(codingPath: [], debugDescription: "Invalid UTF-8 string")
            )
        }
        return try parseFromJSON(data)
    }
}
