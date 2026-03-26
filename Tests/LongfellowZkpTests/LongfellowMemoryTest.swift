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
import Testing
import SwiftCBOR
import MdocDataModel18013
import LongfellowZkp
import OrderedCollections
import XCTest

class LongfellowMemoryTest: XCTestCase {

    func testProofMemoryImpact() async throws {
        let (zkSystem, spec) = try LongfellowZkpTests.loadCircuitAndSpec()
        let zkSystemLf = zkSystem as! LongfellowZkSystem
        let document = try Document(cbor: try CBOR.decode(MdocTestDataProvider.getMdocBytes())!)
        // Generate proof
        self.measure(metrics: [XCTMemoryMetric()]) {
            do {
                let zkDoc = try zkSystemLf.generateProof(zkSystemSpec: spec, document: document, sessionTranscriptBytes: MdocTestDataProvider.getTranscript(), timestamp: Date.now)
                  XCTAssert(zkDoc.proof.count > 0)
            } catch { XCTFail(error.localizedDescription)}
        }
    }
}
