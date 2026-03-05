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
import Logging

/// Represents a single mdoc attribute as a namespace/key/value triple for use in ZK proof operations.
public struct NativeAttribute {
    /// The namespace identifier (e.g. `"org.iso.18013.5.1"`).
    public let namespace: String
    /// The element identifier (e.g. `"age_over_18"`).
    public let key: String
    /// The CBOR-encoded element value.
    public let value: Data

    /// Creates a new `NativeAttribute`.
    /// - Parameters:
    ///   - namespace: The namespace identifier.
    ///   - key: The element identifier.
    ///   - value: The CBOR-encoded element value.
    public init(namespace: String, key: String, value: Data) {
        self.namespace = namespace
        self.key = key
        self.value = value
    }
}

let logger = Logger(label: "LongFellowZkSystem")
