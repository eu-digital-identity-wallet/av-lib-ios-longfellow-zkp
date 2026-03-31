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

/// Represents a loaded ZK circuit file together with its parsed specification.
///
/// A `CircuitEntry` bundles a circuit's binary data location with its
/// ``ZkSystemSpec`` and ``LongfellowZkSystemSpec``, which are parsed
/// from the circuit filename.
public struct CircuitEntry: Sendable {
    /// The generic ZK system specification derived from the circuit filename.
    public let zkSystemSpec: ZkSystemSpec
    /// The Longfellow-specific ZK system specification derived from the circuit filename.
    public let longfellowZkSystemSpec: LongfellowZkSystemSpec
    /// The circuit filename (without path separators).
    public let circuitFilename: String
    /// The file URL pointing to the circuit binary data.
    public let circuitUrl: URL?
    /// The pregenerated circuit binary data
    public let circuitData: Data?

    /// Reads and returns the raw circuit bytes from disk.
    /// - Returns: The circuit binary data.
    /// - Throws: An error if the file cannot be read.
    public func getCircuitBytes() throws -> Data {
        if let circuitData { return circuitData }
        else if let circuitUrl { return try Data(contentsOf: circuitUrl) }
        else { throw NSError(domain: "\(CircuitEntry.self)", code: 0, userInfo: [NSLocalizedDescriptionKey: "Bytes or URL not specified"]) }
    }
    
    /// - Parameters:
    ///   - circuitFilename: the name of the circuit file
    ///   - circuitUrl: the url of the circuit file
    /// - Returns: true if the circuit was added successfully, false otherwise
    public init(circuitFilename: String, circuitUrl: URL) throws {
        let spec = try LongfellowZkSystem.parseCircuitFilename(circuitFilename)
        self.circuitUrl = circuitUrl
        self.circuitData = nil
        self.circuitFilename = circuitFilename
        zkSystemSpec = spec.0
        longfellowZkSystemSpec = spec.1
    }
    
    /// - Parameters:
    ///   - circuitFilename: the name of the circuit file
    ///   - circuitBytes: the data of the circuit file
    /// - Returns: true if the circuit was added successfully, false otherwise
    public init(circuitFilename: String, circuitData: Data) throws {
        let spec = try LongfellowZkSystem.parseCircuitFilename(circuitFilename)
        self.circuitUrl = nil
        self.circuitData = circuitData
        self.circuitFilename = circuitFilename
        zkSystemSpec = spec.0
        longfellowZkSystemSpec = spec.1
    }
    
 
}
