import Foundation
import Security



public extension Keychain {
	
	static func clearAll(ofClass secClass: CFString, in accessGroup: String? = nil) throws {
		var query: [CFString: Any] = [kSecClass: secClass]
		if #available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, *) {
			/* See baseQuery(…) for info about this. */
			query[kSecUseDataProtectionKeychain] = kCFBooleanTrue
		} else {
#if os(macOS)
			throw Err.clearingKeychainOnNonSandboxedEnvironment
#endif
		}
		if let accessGroup {
			query[kSecAttrAccessGroup] = accessGroup
		}
		
		try Keychain.performDelete(query)
	}
	
}
