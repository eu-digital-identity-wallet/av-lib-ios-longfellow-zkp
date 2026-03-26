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
import CryptoKit
import Security

public enum CryptoKitECKeyError: Error {
    case invalidCertificateData
    case failedToCreateCertificate
    case failedToExtractPublicKey
    case failedToGetKeyData
    case unsupportedKeySize(Int)
    case unsupportedKeyAlgorithm
    case notECKey
}

/// Contains detailed information about an extracted EC public key.
@available(iOS 14.0, *)
public struct ECCurveKeyInfo {
    /// The key size in bits (e.g. 256, 384, 521).
    public let keySize: Int
    /// The EC curve type.
    public let keyType: ECCurveType
    /// The raw key data in X9.63 uncompressed representation.
    public let x963KeyData: Data
    /// The underlying `SecKey` reference.
    public let secKey: SecKey
}

/// Represents supported elliptic curve types for EC key extraction.
@available(iOS 14.0, *)
public enum ECCurveType: String, CaseIterable {
    case p256 = "P-256"
    case p384 = "P-384"
    case p521 = "P-521"

    var bitSize: Int {
        switch self {
        case .p256: return 256
        case .p384: return 384
        case .p521: return 521
        }
    }

    var cryptoKitType: String {
        return "EC \(self.rawValue) (\(bitSize)-bit)"
    }

    /// Returns the `ECCurveType` matching the given bit size, or `nil` if unsupported.
    /// - Parameter bitSize: The key size in bits.
    /// - Returns: The matching curve type, or `nil`.
    public static func from(bitSize: Int) -> ECCurveType? {
        switch bitSize {
        case 256: return .p256
        case 384: return .p384
        case 521: return .p521
        default: return nil
        }
    }
}

@available(iOS 14.0, *)
public class ECKeyExtractor {

    // MARK: - Method 1: Extract with Automatic Detection and Type Conversion

    /// Extracts EC public key from certificate and converts to appropriate CryptoKit type
    public static func extractECCKey(from certificateData: Data) throws -> Any {
        let (key, keyType) = try detectAndConvertECCKey(from: certificateData)

        switch keyType {
        case .p256:
            guard let p256Key = key as? P256.Signing.PublicKey else {
                throw CryptoKitECKeyError.unsupportedKeyAlgorithm
            }
            return p256Key

        case .p384:
            guard let p384Key = key as? P384.Signing.PublicKey else {
                throw CryptoKitECKeyError.unsupportedKeyAlgorithm
            }
            return p384Key

        case .p521:
            guard let p521Key = key as? P521.Signing.PublicKey else {
                throw CryptoKitECKeyError.unsupportedKeyAlgorithm
            }
            return p521Key
        }
    }

    // MARK: - Method 2: Extract with Specific Type Assertion

    /// Extracts EC key asserting it's of a specific type
    public static func extractECCKey<T>(from certificateData: Data, as type: T.Type) throws -> T {
        let (key, keyType) = try detectAndConvertECCKey(from: certificateData)

        // Verify expected type
        switch (type, keyType) {
        case (is P256.Signing.PublicKey.Type, .p256):
            guard let typedKey = key as? T else {
                throw CryptoKitECKeyError.unsupportedKeyAlgorithm
            }
            return typedKey

        case (is P384.Signing.PublicKey.Type, .p384):
            guard let typedKey = key as? T else {
                throw CryptoKitECKeyError.unsupportedKeyAlgorithm
            }
            return typedKey

        case (is P521.Signing.PublicKey.Type, .p521):
            guard let typedKey = key as? T else {
                throw CryptoKitECKeyError.unsupportedKeyAlgorithm
            }
            return typedKey

        default:
            throw CryptoKitECKeyError.unsupportedKeyAlgorithm
        }
    }

    // MARK: - Method 3: Extract Complete Key Information

    /// Extracts all key information including raw data and metadata
    public static func extractECCKeyInfo(from certificateData: Data) throws -> ECCurveKeyInfo {
        let (key, keyType, keyData, secKey) = try extractKeyComponents(from: certificateData)
        _ = key // Unused, but extracted for validation
        return ECCurveKeyInfo(
            keySize: keyType.bitSize,
            keyType: keyType,
            x963KeyData: keyData,
            secKey: secKey
        )
    }

    // MARK: - Method 4: Extract and Verify Size

    /// Extracts key and verifies it matches expected size
    public static func extractECCKeyWithSizeVerification(from certificateData: Data,
                                                 expectedSize: Int) throws -> Any {
        let (key, keyType) = try detectAndConvertECCKey(from: certificateData)

        guard keyType.bitSize == expectedSize else {
            throw CryptoKitECKeyError.unsupportedKeySize(keyType.bitSize)
        }

        return key
    }

    // MARK: - Helper Methods

    /// Detects the EC curve type from a DER-encoded certificate and converts it to the appropriate CryptoKit key type.
    /// - Parameter certificateData: The DER-encoded X.509 certificate data.
    /// - Returns: A tuple containing the CryptoKit public key and its curve type.
    /// - Throws: A `CryptoKitECKeyError` if the certificate is invalid or the key type is unsupported.
    public static func detectAndConvertECCKey(from certificateData: Data) throws -> (key: Any, type: ECCurveType) {
        let (key, keyType, _, _) = try extractKeyComponents(from: certificateData)
        return (key, keyType)
    }

    private static func extractKeyComponents(from certificateData: Data) throws ->
    (cryptoKitKey: Any, curveType: ECCurveType, rawData: Data, secKey: SecKey) {
        // 1. Create certificate from data
        guard let certificate = SecCertificateCreateWithData(nil, certificateData as CFData) else {
            throw CryptoKitECKeyError.invalidCertificateData
        }
        // 2. Extract public key
        guard let secKey = SecCertificateCopyKey(certificate) else {
            throw CryptoKitECKeyError.failedToExtractPublicKey
        }
        // 3. Get key attributes to verify it's EC
        guard let attributes = SecKeyCopyAttributes(secKey) as? [String: Any] else {
            throw CryptoKitECKeyError.failedToGetKeyData
        }
        // 4. Verify it's an EC key
        guard let keyType = attributes[kSecAttrKeyType as String] as? String,
              keyType == kSecAttrKeyTypeEC as String else {
            throw CryptoKitECKeyError.notECKey
        }
        // 5. Get key size
        guard let keySize = attributes[kSecAttrKeySizeInBits as String] as? Int else {
            throw CryptoKitECKeyError.failedToGetKeyData
        }
        // 6. Determine EC curve type
        guard let curveType = ECCurveType.from(bitSize: keySize) else {
            throw CryptoKitECKeyError.unsupportedKeySize(keySize)
        }
        // 7. Get raw key data
        var error: Unmanaged<CFError>?
        guard let keyData = SecKeyCopyExternalRepresentation(secKey, &error) as Data? else {
            throw error?.takeRetainedValue() ?? CryptoKitECKeyError.failedToGetKeyData
        }
        // 8. Convert to appropriate CryptoKit type
        let cryptoKitKey: Any
        switch curveType {
        case .p256:
            cryptoKitKey = try P256.Signing.PublicKey(x963Representation: keyData)
        case .p384:
            cryptoKitKey = try P384.Signing.PublicKey(x963Representation: keyData)
        case .p521:
            cryptoKitKey = try P521.Signing.PublicKey(x963Representation: keyData)
        }
        return (cryptoKitKey, curveType, keyData, secKey)
    }

    // MARK: - Size Detection Methods

    /// Detects the EC curve type from DER-encoded certificate data.
    /// - Parameter certificateData: The DER-encoded X.509 certificate data.
    /// - Returns: The detected ``ECCurveType``.
    /// - Throws: A `CryptoKitECKeyError` if the certificate is invalid or the key type is unsupported.
    public static func detectECCurveType(from certificateData: Data) throws -> ECCurveType {
        let (_, curveType) = try detectAndConvertECCKey(from: certificateData)
        return curveType
    }

    /// Gets the EC key size in bits from a DER-encoded certificate.
    /// - Parameter certificateData: The DER-encoded X.509 certificate data.
    /// - Returns: The key size in bits (e.g. 256, 384, 521).
    /// - Throws: A `CryptoKitECKeyError` if the certificate is invalid.
    public static func getKeySizeInBits(from certificateData: Data) throws -> Int {
        let curveType = try detectECCurveType(from: certificateData)
        return curveType.bitSize
    }

    /// Checks if a certificate contains an EC key of a specific curve type.
    /// - Parameters:
    ///   - curveType: The expected ``ECCurveType``.
    ///   - certificateData: The DER-encoded X.509 certificate data.
    /// - Returns: `true` if the certificate's key matches the given curve type, `false` otherwise.
    public static func isECCurveType(_ curveType: ECCurveType, in certificateData: Data) -> Bool {
        do {
            let detectedType = try detectECCurveType(from: certificateData)
            return detectedType == curveType
        } catch {
            return false
        }
    }
}

// MARK: - Convenience Extensions

@available(iOS 14.0, *)
extension P256.Signing.PublicKey {
    /// Creates a P-256 signing public key from a DER-encoded X.509 certificate.
    /// - Parameter certificateData: The DER-encoded certificate data.
    /// - Returns: The extracted P-256 public key.
    /// - Throws: A `CryptoKitECKeyError` if the certificate does not contain a P-256 key.
    public static func fromCertificate(_ certificateData: Data) throws -> Self {
        return try ECKeyExtractor.extractECCKey(from: certificateData, as: Self.self)
    }
}

@available(iOS 14.0, *)
extension P384.Signing.PublicKey {
    /// Creates a P-384 signing public key from a DER-encoded X.509 certificate.
    /// - Parameter certificateData: The DER-encoded certificate data.
    /// - Returns: The extracted P-384 public key.
    /// - Throws: A `CryptoKitECKeyError` if the certificate does not contain a P-384 key.
    public static func fromCertificate(_ certificateData: Data) throws -> Self {
        return try ECKeyExtractor.extractECCKey(from: certificateData, as: Self.self)
    }
}

@available(iOS 14.0, *)
extension P521.Signing.PublicKey {
    /// Creates a P-521 signing public key from a DER-encoded X.509 certificate.
    /// - Parameter certificateData: The DER-encoded certificate data.
    /// - Returns: The extracted P-521 public key.
    /// - Throws: A `CryptoKitECKeyError` if the certificate does not contain a P-521 key.
    public static func fromCertificate(_ certificateData: Data) throws -> Self {
        return try ECKeyExtractor.extractECCKey(from: certificateData, as: Self.self)
    }
}

// MARK: - Sample Usage with Simplified API

@available(iOS 14.0, *)
func extractECPublicKey(certificateData: Data) -> Result<Any, CryptoKitECKeyError> {
    do {
        let key = try ECKeyExtractor.extractECCKey(from: certificateData)
        return .success(key)
    } catch let error as CryptoKitECKeyError {
        return .failure(error)
    } catch {
        return .failure(.unsupportedKeyAlgorithm)
    }
}


