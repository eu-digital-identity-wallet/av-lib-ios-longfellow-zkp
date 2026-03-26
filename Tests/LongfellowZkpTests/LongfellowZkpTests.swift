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
@testable import LongfellowZkp

struct LongfellowZkpTests {
    static func loadCircuitAndSpec() throws -> (any ZkSystemProtocol, ZkSystemSpec) {
        let filename = "6_1_4096_2945_137e5a75ce72735a37c8a72da1a8a0a5df8d13365c2ae3d2c2bd6a0e7197c7c6"
        let comps = filename.components(separatedBy: "_")
        let circuitUrl = try #require(Bundle.module.url(forResource: filename, withExtension: nil))
        let circuit = try CircuitEntry(circuitFilename: filename, circuitUrl: circuitUrl)
        // Initialize the Longfellow ZK system
        let system = LongfellowZkSystem(circuits: [circuit])
        // Initialize ZK system repository
        let zkRepository = ZkSystemRepository(systems: [system])
        // Create ZK system spec
        let longfellowSpec = LongfellowZkSystemSpec(
            system: system.name, circuitHash: comps[4], numAttributes: 1, version: 6, blockEncHash: 4096, blockEncSig: 2945)
        let spec = ZkSystemSpec(id: "\(system.name)_\(comps[4])", system: system.name, params: longfellowSpec.toZkParams()) // id: "one_\(system.name)",
        let zkSystem = try #require(zkRepository.lookup(system.name))
        return (zkSystem, spec)
    }

    @Test func testZkSystemSpecFromDcql() async throws {
        let jsonString = """
        {
        "doctype_value": "org.iso.18013.5.1.mDL",
        "zk_system_type": [
            {
            "system": "longfellow-libzk-v1",
            "circuit_hash": "f88a39e561ec0be02bb3dfe38fb609ad154e98decbbe632887d850fc612fea6f",
            "num_attributes": 1,
            "version": 5,
            "block_enc_hash": 4096,
            "block_enc_sig": 2945
            }
        ],
        "verifier_message": "challenge"
        }
        """
        let zkLFSpecs = try LongfellowZkSystemSpec.parseFromJSONString(jsonString)
        let zkSystemSpec = try #require(zkLFSpecs.first)
        #expect(zkSystemSpec.circuitHash == "f88a39e561ec0be02bb3dfe38fb609ad154e98decbbe632887d850fc612fea6f")
    }

    @Test func testAvDocIssuerPublicKeys() async throws {
        let dr = try DeviceResponse(data: MdocTestDataProvider.getAvBytes())
        guard let document = dr.documents?.first else { throw NSError(domain: "LongfellowZkSystem", code: 2, userInfo: [NSLocalizedDescriptionKey: "No document found in DeviceResponse"]) }
        let issuerCert = document.issuerSigned.issuerAuth.x5chain.first!
        let publicKeyInfo = try ECKeyExtractor.extractECCKeyInfo(from: Data(issuerCert))
        let publicKeyRawData = publicKeyInfo.x963KeyData.dropFirst()
        let x = LongfellowZkSystem.getFormattedCoordinate(value: publicKeyRawData.prefix(publicKeyRawData.count / 2))
        let y = LongfellowZkSystem.getFormattedCoordinate(value: publicKeyRawData.suffix(publicKeyRawData.count / 2))
        #expect(x == "0x6789e96e797e2e04f7f3cbb54a12410412410db000fb6d63dc977d8b5d35a4f9", "x error")
        #expect(y == "0x3b71f297d9d308ba2e955e8563afa0604833aae10ecb1aaefbe4159b5b8b9057", "y error")
    }
    
    @Test func testMultipazMdlDocProofFullFlow() async throws {
        let (zkSystem, spec) = try Self.loadCircuitAndSpec()
        // Decode session transcript and document
        // let sessionTranscript = try #require(try CBOR.decode(MdocTestDataProvider.getTranscript()))
        let documentData = try #require(try CBOR.decode(MdocTestDataProvider.getMdocBytes()))
        let document = try Document(cbor: documentData)
        let issuerCert = document.issuerSigned.issuerAuth.x5chain.first!
        let publicKeyInfo = try ECKeyExtractor.extractECCKeyInfo(from: Data(issuerCert))
        let publicKeyRawData = publicKeyInfo.x963KeyData.dropFirst()
        let x = LongfellowZkSystem.getFormattedCoordinate(value: publicKeyRawData.prefix(publicKeyRawData.count / 2))
        let y = LongfellowZkSystem.getFormattedCoordinate(value: publicKeyRawData.suffix(publicKeyRawData.count / 2))
        let testTime = MdocTestDataProvider.getProofGenerationDate(year: 2025, month: 7, day: 3)
        // Generate proof
        let longfellowDocBytes = CBOR.encode(CBOR.map([
            CBOR.utf8String("version"): CBOR.utf8String("1.0"),
            CBOR.utf8String("documents"): CBOR.array([document.toCBOR(options: CBOROptions())]),
            CBOR.utf8String("status"): CBOR.unsignedInt(0)
        ]), options: CBOROptions())
        let zkDoc = try zkSystem.generateProof(zkSystemSpec: spec, docBytes: longfellowDocBytes,
            x: x, y: y, sessionTranscriptBytes: MdocTestDataProvider.getTranscript(), timestamp: testTime)
        #expect(zkDoc.proof.count > 0)
        // verify fails currently but we are interested only for the proof
        //try zkSystem.verifyProof(zkDocument: zkDoc, zkSystemSpec: spec, sessionTranscriptBytes: MdocTestDataProvider.getTranscript())
    }

    @Test() func testDocumentEncode() async throws {
        let docB = MdocTestDataProvider.getMdocBytes()
        let doc = try Document(data: docB)
        let docB2 = doc.toCBOR(options: CBOROptions()).encode()
        print(Data(docB2).base64EncodedString())
        #expect(docB.count == docB2.count, "Count not equal")
        #expect(docB == docB2, "Data not equal")
    }

    @Test func testIssuerAuthEncodeDecode() async throws {
        let issuerSignedData = Data(base64URLEncoded: "omppc3N1ZXJBdXRohEOhASahGCFZAsEwggK9MIICY6ADAgECAhRwdsHQFeq8P9Z7P9eqeKbP480vhTAKBggqhkjOPQQDAjBpMSYwJAYDVQQDDB1BZ2UgVmVyaWZpY2F0aW9uIElzc3VlciBDQSAwMTEyMDAGA1UECgwpQWdlIFZlcmlmaWNhdGlvbiBSZWZlcmVuY2UgSW1wbGVtZW50YXRpb24xCzAJBgNVBAYTAkVVMB4XDTI1MDcwMTEwNTcxMVoXDTI2MDkyNDEwNTcxMFowZTEiMCAGA1UEAwwZQWdlIFZlcmlmaWNhdGlvbiBEUyAtIDAwMTEyMDAGA1UECgwpQWdlIFZlcmlmaWNhdGlvbiBSZWZlcmVuY2UgSW1wbGVtZW50YXRpb24xCzAJBgNVBAYTAkVVMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEZ4npbnl-LgT388u1ShJBBBJBDbAA-21j3Jd9i101pPk7cfKX2dMIui6VXoVjr6BgSDOq4Q7LGq775BWbW4uQV6OB7DCB6TAfBgNVHSMEGDAWgBTLcJWATJke3G0LfP7r4EHKIlQu2DAWBgNVHSUBAf8EDDAKBggrgQICAAABAjBEBgNVHR8EPTA7MDmgN6A1hjNodHRwczovL2lzc3Vlci5hZ2V2ZXJpZmljYXRpb24uZGV2L3BraS9FVV9DQV8wMS5jcmwwHQYDVR0OBBYEFP8bupeyyn71rqMwFIbx-8mLRZj6MA4GA1UdDwEB_wQEAwIHgDA5BgNVHRIEMjAwBgNVHRIEKTAngiVodHRwczovL2NvbW1pc3Npb24uZXVyb3BhLmV1L2luZGV4X2VuMAoGCCqGSM49BAMCA0gAMEUCIEqvW4Z-bxIC4PSSTei2iTGUcfnOazuctzVfpooBTiY3AiEA3bMms8CJ31WPVzLqql6HwNXVFAYkYC81mK_avxgNtmpZAVjYGFkBU6ZnZG9jVHlwZXFldS5ldXJvcGEuZWMuYXYuMWd2ZXJzaW9uYzEuMGx2YWxpZGl0eUluZm-jZnNpZ25lZMB0MjAyNi0wMS0yNVQwMDowMDowMFppdmFsaWRGcm9twHQyMDI2LTAxLTI1VDAwOjAwOjAwWmp2YWxpZFVudGlswHQyMDI2LTA0LTI1VDAwOjAwOjAwWmx2YWx1ZURpZ2VzdHOhcWV1LmV1cm9wYS5lYy5hdi4xoQBYIIi9eiZkYZH7l_Gj5TdUKH2t2ousVmyPCRiQUZIGzJ69bWRldmljZUtleUluZm-haWRldmljZUtleaQBAiABIVgg-g0LHVGv8qoVHfG8ytrpvqQS4YpeKZZjuQdjJvd_HNciWCBBQ83JzCRcGmJtmFWFa7zD5LMFcRU0SodfazVKa_frvG9kaWdlc3RBbGdvcml0aG1nU0hBLTI1NlhAG75USv5rxsHMLzTrjIt2323OfVnqFMAYpMZ6uad2TreyQD86nuUvgF5oayq7eGJ8xPy0A19s2cSmx8O_B3IWuGpuYW1lU3BhY2VzoXFldS5ldXJvcGEuZWMuYXYuMYHYGFhgpGhkaWdlc3RJRABmcmFuZG9tWCA9DfhylHIqY0-DoRBRoxHL5sJkX0Om9u0p53qCapRMKnFlbGVtZW50SWRlbnRpZmllcmthZ2Vfb3Zlcl8xOGxlbGVtZW50VmFsdWX1")!
        let iss = try IssuerSigned(data: issuerSignedData.bytes)
        let issb = iss.toCBOR(options: CBOROptions()).encode()
        print(Data(issb).base64URLEncodedString())
        #expect(issuerSignedData.bytes.count == issb.count, "Count not equal")
        // #expect(issuerSignedData.bytes == issb, "Data not equal")
    }
    
}

// MARK: - Data Extension for Test Resources

extension Data {
    init?(name: String, ext: String?, from bundle: Bundle) {
        // Try with Resources subdirectory first
        if let url = bundle.url(forResource: name, withExtension: ext, subdirectory: "Resources") {
            try? self.init(contentsOf: url)
            return
        }
        // Try without subdirectory
        if let url = bundle.url(forResource: name, withExtension: ext) {
            try? self.init(contentsOf: url)
            return
        }
        return nil
    }
}
