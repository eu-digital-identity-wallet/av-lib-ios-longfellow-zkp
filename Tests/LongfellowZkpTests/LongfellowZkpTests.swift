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
        let filename = "7_1_4151_4096_8d079211715200ff06c5109639245502bfe94aa869908d31176aae4016182121"
        let comps = filename.components(separatedBy: "_")
        let circuitUrl = try #require(Bundle.module.url(forResource: filename, withExtension: nil))
        let circuit = try CircuitEntry(circuitFilename: filename, circuitUrl: circuitUrl)
        // Initialize the Longfellow ZK system
        let system = LongfellowZkSystem(circuits: [circuit])
        // Initialize ZK system repository
        let zkRepository = ZkSystemRepository(systems: [system])
        // Create ZK system spec
        let longfellowSpec = LongfellowZkSystemSpec(
            system: system.name, circuitHash: comps[4], numAttributes: 1, version: 7, blockEncHash: 4151, blockEncSig: 4096)
        let spec = ZkSystemSpec(zkSystemId: "\(system.name)_\(comps[4])", system: system.name, params: longfellowSpec.toZkParams()) // id: "one_\(system.name)",
        let zkSystem = try #require(zkRepository.lookup(system.name))
        return (zkSystem, spec)
    }
    
    static func generateCircuitAndSpec() throws -> (any ZkSystemProtocol, ZkSystemSpec) {
        let specLf = LongfellowNatives.getLongfellowZkSystemSpec(numAttributes: 1)
        let circuitData = LongfellowNatives.generateCircuit(jzkSpec: specLf)
        let filename = "\(specLf.version)_\(specLf.numAttributes)_\(specLf.blockEncHash)_\(specLf.blockEncSig)_\(specLf.circuitHash)"
        let circuit = try CircuitEntry(circuitFilename: filename, circuitData: circuitData)
        let system = LongfellowZkSystem(circuits: [circuit])
        // Initialize ZK system repository
        let zkRepository = ZkSystemRepository(systems: [system])
        // Create ZK system spec
        let longfellowSpec = LongfellowZkSystemSpec(
            system: system.name, circuitHash: specLf.circuitHash, numAttributes: 1, version: Int64(specLf.version), blockEncHash: Int64(specLf.blockEncHash), blockEncSig: Int64(specLf.blockEncSig))
        let spec = ZkSystemSpec(zkSystemId: "\(system.name)_\(specLf.circuitHash)", system: system.name, params: longfellowSpec.toZkParams()) // id: "one_\(system.name)",
        let zkSystem = try #require(zkRepository.lookup(system.name))
        return (zkSystem, spec)
    }
    
    
    static func generateProof(_ zkSystem: any ZkSystemProtocol, _ spec: ZkSystemSpec) throws -> ZkDocument {
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
       return zkDoc
    }

    @Test func testProofInputsPreserveOrderThroughDeviceResponse() throws {
        let elementNames = ["z_last", "age_above18", "a_first", "age_above60"]
        let items = try elementNames.enumerated().map { index, name in
            try IssuerSignedItem(cbor: .map([
                .utf8String("digestID"): .unsignedInt(UInt64(index)),
                .utf8String("random"): .byteString([UInt8(index)]),
                .utf8String("elementIdentifier"): .utf8String(name),
                .utf8String("elementValue"): .unsignedInt(UInt64(index))
            ]))
        }
        let namespaces = IssuerNameSpaces(nameSpaces: [
            "z.namespace": items,
            "a.namespace": Array(items.reversed()),
            "m.namespace": items
        ])
        let (issuerSigned, attributes) = LongfellowZkSystem.makeProofInputs(issuerNameSpaces: namespaces)
        let expectedNamespaces = Array(namespaces.nameSpaces.keys)
        #expect(Array(issuerSigned.keys) == expectedNamespaces)
        for namespace in expectedNamespaces {
            let expectedItems = try #require(namespaces[namespace])
            #expect(Array(try #require(issuerSigned[namespace]).keys) == expectedItems.map(\.elementIdentifier))
        }
        let expectedItems = expectedNamespaces.flatMap { namespace in
            namespaces[namespace]!.map { (namespace, $0) }
        }
        #expect(attributes.map(\.namespace) == expectedItems.map { $0.0 })
        #expect(attributes.map(\.key) == expectedItems.map { $0.1.elementIdentifier })
        #expect(attributes.map(\.value) == expectedItems.map { Data($0.1.elementValue.encode()) })

        let document = ZkDocument(documentData: ZkDocumentData(
            zkSystemSpecId: "test-spec", docType: "test-doctype",
            timestamp: Date(timeIntervalSince1970: 1_750_000_000),
            issuerSigned: issuerSigned, deviceSigned: [:], msoX5chain: nil
        ), proof: Data([1, 2, 3]))
        let response = DeviceResponse(zkDocuments: [document])
        let decoded = try DeviceResponse(data: response.toCBOR(options: CBOROptions()).encode())
        let decodedDocument = try #require(decoded.zkDocuments?.first)
        #expect(decodedDocument.documentDataBytes == document.documentDataBytes)
        #expect(Array(decodedDocument.documentData.issuerSigned.keys) == expectedNamespaces)
        let decodedAttributes = decodedDocument.documentData.issuerSigned.flatMap { namespace, elements in
            elements.map { NativeAttribute(namespace: namespace, key: $0.key, value: Data($0.value.encode())) }
        }
        #expect(decodedAttributes.map(\.namespace) == attributes.map(\.namespace))
        #expect(decodedAttributes.map(\.key) == attributes.map(\.key))
        #expect(decodedAttributes.map(\.value) == attributes.map(\.value))
    }

    @Test func testProofInputsWithoutIssuerNamespaces() {
        let (issuerSigned, attributes) = LongfellowZkSystem.makeProofInputs(issuerNameSpaces: nil)
        #expect(issuerSigned.isEmpty)
        #expect(attributes.isEmpty)
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
        #expect(zkSystemSpec.circuitHash == "f88a39e561ec0be02bb3dfe38fb609ad154e98decbbe632887d850fc612fea6f", "The parsed DCQL specification should preserve the circuit hash")
    }

    @Test func testMultipazMdlDocProofAndVerifyFlow() async throws {
        let (zkSystem, spec) = try Self.loadCircuitAndSpec()
        let zkDoc = try Self.generateProof(zkSystem, spec)
        #expect(!zkDoc.proof.isEmpty)
        let response = DeviceResponse(zkDocuments: [zkDoc])
        let decoded = try DeviceResponse(data: response.toCBOR(options: CBOROptions()).encode())
        let decodedDocument = try #require(decoded.zkDocuments?.first)
        try zkSystem.verifyProof(zkDocument: decodedDocument, zkSystemSpec: spec, sessionTranscriptBytes: MdocTestDataProvider.getTranscript())
        try zkSystem.verifyProof(zkDocument: zkDoc, zkSystemSpec: spec, sessionTranscriptBytes: MdocTestDataProvider.getTranscript())
        #expect(throws: ProofVerificationFailureException.self) {
            try zkSystem.verifyProof(zkDocument: zkDoc, zkSystemSpec: spec, sessionTranscriptBytes: MdocTestDataProvider.getTranscript() + [0])
        }
    }
    
    @Test func testLongfellowMdlDocProofFlow() async throws {
        let (zkSystem, spec) = try Self.generateCircuitAndSpec()
        let zkDoc = try Self.generateProof(zkSystem, spec)
        #expect(zkDoc.proof.count > 0, "The generated mDL proof should contain bytes")
        try zkSystem.verifyProof(zkDocument: zkDoc, zkSystemSpec: spec, sessionTranscriptBytes: MdocTestDataProvider.getTranscript())
    }

    @Test() func testDocumentEncode() async throws {
        let docB = MdocTestDataProvider.getMdocBytes()
        let doc = try Document(data: docB)
        let docB2 = doc.toCBOR(options: CBOROptions()).encode()
        print(Data(docB2).base64EncodedString())
        #expect(docB.count == docB2.count, "Re-encoding the document should preserve its byte count")
        #expect(docB == docB2, "Re-encoding the document should preserve its CBOR bytes")
    }

    @Test func testGetLongfellowZkSystemSpecReturnsValidSpec() async throws {
        let spec = LongfellowNatives.getLongfellowZkSystemSpec(numAttributes: 1)
        #expect(spec.system == "longfellow-libzk-v1", "The native specification should identify the Longfellow ZK system")
        #expect(spec.numAttributes == 1, "The native specification should support the requested single attribute")
        #expect(spec.circuitHash.isEmpty == false, "The native specification should provide a circuit hash")
        #expect(spec.version > 0, "The native specification version should be positive")
        #expect(spec.blockEncHash > 0, "The hash block encoding parameter should be positive")
        #expect(spec.blockEncSig > 0, "The signature block encoding parameter should be positive")
    }

    @Test func testGetLongfellowZkSystemSpecCircuitFilename() async throws {
        let spec = LongfellowNatives.getLongfellowZkSystemSpec(numAttributes: 1)
        // The known circuit filename encodes: version_numAttributes_blockEncHash_blockEncSig_circuitHash
        let filename = "\(spec.version)_\(spec.numAttributes)_\(spec.blockEncHash)_\(spec.blockEncSig)_\(spec.circuitHash)"
        print(filename)
    }

    @Test(arguments: 1...4)
    func testGenerateCircuitMatchesFixture(numAttributes: Int) throws {
        let spec = LongfellowNatives.getLongfellowZkSystemSpec(numAttributes: numAttributes)
        let circuitData = LongfellowNatives.generateCircuit(jzkSpec: spec)
        let filename = "\(spec.version)_\(spec.numAttributes)_\(spec.blockEncHash)_\(spec.blockEncSig)_\(spec.circuitHash)"
        let fixtureURL = try #require(Bundle.module.url(forResource: filename, withExtension: nil))
        let fixtureData = try Data(contentsOf: fixtureURL)
        #expect(!circuitData.isEmpty)
        #expect(circuitData == fixtureData)
    }

    @Test func testIssuerAuthEncodeDecode() async throws {
        let issuerSignedData = Data(base64URLEncoded: "omppc3N1ZXJBdXRohEOhASahGCFZAsEwggK9MIICY6ADAgECAhRwdsHQFeq8P9Z7P9eqeKbP480vhTAKBggqhkjOPQQDAjBpMSYwJAYDVQQDDB1BZ2UgVmVyaWZpY2F0aW9uIElzc3VlciBDQSAwMTEyMDAGA1UECgwpQWdlIFZlcmlmaWNhdGlvbiBSZWZlcmVuY2UgSW1wbGVtZW50YXRpb24xCzAJBgNVBAYTAkVVMB4XDTI1MDcwMTEwNTcxMVoXDTI2MDkyNDEwNTcxMFowZTEiMCAGA1UEAwwZQWdlIFZlcmlmaWNhdGlvbiBEUyAtIDAwMTEyMDAGA1UECgwpQWdlIFZlcmlmaWNhdGlvbiBSZWZlcmVuY2UgSW1wbGVtZW50YXRpb24xCzAJBgNVBAYTAkVVMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEZ4npbnl-LgT388u1ShJBBBJBDbAA-21j3Jd9i101pPk7cfKX2dMIui6VXoVjr6BgSDOq4Q7LGq775BWbW4uQV6OB7DCB6TAfBgNVHSMEGDAWgBTLcJWATJke3G0LfP7r4EHKIlQu2DAWBgNVHSUBAf8EDDAKBggrgQICAAABAjBEBgNVHR8EPTA7MDmgN6A1hjNodHRwczovL2lzc3Vlci5hZ2V2ZXJpZmljYXRpb24uZGV2L3BraS9FVV9DQV8wMS5jcmwwHQYDVR0OBBYEFP8bupeyyn71rqMwFIbx-8mLRZj6MA4GA1UdDwEB_wQEAwIHgDA5BgNVHRIEMjAwBgNVHRIEKTAngiVodHRwczovL2NvbW1pc3Npb24uZXVyb3BhLmV1L2luZGV4X2VuMAoGCCqGSM49BAMCA0gAMEUCIEqvW4Z-bxIC4PSSTei2iTGUcfnOazuctzVfpooBTiY3AiEA3bMms8CJ31WPVzLqql6HwNXVFAYkYC81mK_avxgNtmpZAVjYGFkBU6ZnZG9jVHlwZXFldS5ldXJvcGEuZWMuYXYuMWd2ZXJzaW9uYzEuMGx2YWxpZGl0eUluZm-jZnNpZ25lZMB0MjAyNi0wMS0yNVQwMDowMDowMFppdmFsaWRGcm9twHQyMDI2LTAxLTI1VDAwOjAwOjAwWmp2YWxpZFVudGlswHQyMDI2LTA0LTI1VDAwOjAwOjAwWmx2YWx1ZURpZ2VzdHOhcWV1LmV1cm9wYS5lYy5hdi4xoQBYIIi9eiZkYZH7l_Gj5TdUKH2t2ousVmyPCRiQUZIGzJ69bWRldmljZUtleUluZm-haWRldmljZUtleaQBAiABIVgg-g0LHVGv8qoVHfG8ytrpvqQS4YpeKZZjuQdjJvd_HNciWCBBQ83JzCRcGmJtmFWFa7zD5LMFcRU0SodfazVKa_frvG9kaWdlc3RBbGdvcml0aG1nU0hBLTI1NlhAG75USv5rxsHMLzTrjIt2323OfVnqFMAYpMZ6uad2TreyQD86nuUvgF5oayq7eGJ8xPy0A19s2cSmx8O_B3IWuGpuYW1lU3BhY2VzoXFldS5ldXJvcGEuZWMuYXYuMYHYGFhgpGhkaWdlc3RJRABmcmFuZG9tWCA9DfhylHIqY0-DoRBRoxHL5sJkX0Om9u0p53qCapRMKnFlbGVtZW50SWRlbnRpZmllcmthZ2Vfb3Zlcl8xOGxlbGVtZW50VmFsdWX1")!
        let iss = try IssuerSigned(data: issuerSignedData.bytes)
        let issb = iss.toCBOR(options: CBOROptions()).encode()
        print(Data(issb).base64URLEncodedString())
        #expect(issuerSignedData.bytes.count == issb.count, "Re-encoding the issuer-signed data should preserve its byte count")
        // #expect(issuerSignedData.bytes == issb, "Re-encoding the issuer-signed data should preserve its CBOR bytes")
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
