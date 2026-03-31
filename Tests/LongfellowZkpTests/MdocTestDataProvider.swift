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
import SwiftCBOR
import LongfellowZkp

class MdocTestDataProvider {
    static func x() -> String {
        return "0x7cd7a1b628ecc8c6a9cf26a040887928f74b559a989b6b17806cbd82794df37c"
    }

    static func y() -> String {
        return "0x539fe8e57647c75b971bbce4a66e2894beb3d349bee11b1499ecf928496a9137"
    }

    static func getAgeOver18DataItems(isOver18: Bool) -> [CBOR] {
        [ .map([.utf8String("elementIdentifier"): .utf8String("age_over_18")]),
          .map([.utf8String("elementValue"): .boolean(isOver18)]),
        ]
    }

    static func getAgeOver18Attributes(isOver18: Bool) -> [NativeAttribute] {
        let dataItemAttributes = getAgeOver18DataItems(isOver18: isOver18)
        var attributes: [NativeAttribute] = []

        for attr in dataItemAttributes {
            guard case let .map(map) = attr, case let .utf8String(elementIdentifier) = map[.utf8String("elementIdentifier")], let elementValue = map[.utf8String("elementValue")] else { continue }
            attributes.append(NativeAttribute(
                namespace: "org.iso.18013.5.1", key: elementIdentifier,
                value: Data(elementValue.encode())
            ))
        }
        return attributes
    }

    static func getProofGenerationDate(year: Int, month: Int, day: Int = 1) -> Date {
        var components = DateComponents()
        components.year = year
        components.month = month
        components.day = day
        components.hour = 0
        components.minute = 0
        components.second = 0

        let calendar = Calendar.current
        return calendar.date(from: components)!
    }

    static func getTranscript() -> [UInt8] {
        [UInt8](Data(base64Encoded: "g9gYWHSjAGMxLjABggHYGFhLpAECIAEhWCDS4AwqiwoJCtCaV1wc7fGngnSP6ULFnHZtfM/dru0WqyJYIP9UbZR+nV+3N2rOsffEiBMw6snngQhH6k5cYsM0I2k9AoGDAgGjAPQB9QtQE2/D4yCbQZGaztBuNP26o9gYWEukAQIgASFYIM6xRCQSV+9S78iyS2L3rgwpNd6/cnI5eb4EgSOaL4YqIlggdHQ1kHMK9k+0k9ye5PdzogPWBS2ABD3LqJM0DCGRoVP2")!)
    }

    static func getMdocBytes() -> [UInt8] {
        [UInt8](Data(base64Encoded: "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")!)
     }


}
