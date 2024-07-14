import Foundation
import Security



public enum Keychain {
	
	public static func getStoredData(withIdentifier identifier: String, accessGroup: String? = nil, username: String = "") throws -> Data? {
		var query = try baseQuery(forIdentifier: identifier, accessGroup: accessGroup, username: username)
		query[kSecMatchLimit]          = kSecMatchLimitOne
		query[kSecReturnData]          = kCFBooleanTrue
		query[kSecReturnRef]           = kCFBooleanFalse
		query[kSecReturnPersistentRef] = kCFBooleanFalse
		query[kSecReturnAttributes]    = kCFBooleanFalse
		
		var searchResult: CFTypeRef?
		let error = SecItemCopyMatching(query as CFDictionary, &searchResult)
		switch error {
			case errSecSuccess:
				guard let result = searchResult as? Data else {
					throw Err.invalidResponseFromSecurityFramework
				}
				return result
				
			case errSecItemNotFound:
				return nil
				
			default:
				throw Err(statusCode: error)
		}
	}
	
	/** Setting data to nil just removes the entry in the keychain. */
	public static func setStoredData(_ data: Data?, withIdentifier identifier: String, accessGroup: String? = nil, username: String = "") throws {
		guard let data = data else {
			try removeStoredData(withIdentifier: identifier, accessGroup: accessGroup, username: username)
			return
		}
		
		var query = try baseQuery(forIdentifier: identifier, accessGroup: accessGroup, username: username)
		let updatedProperties: [CFString: Any] = [
			kSecValueData:       data,
			kSecAttrIsInvisible: kCFBooleanFalse as Any,
			kSecAttrAccessible:  kSecAttrAccessibleAfterFirstUnlock
		]
		
		/* First we try and update the existing property.
		 * If the property does not exist, we will process the error and use SecItemAdd. */
		var saveError = SecItemUpdate(query as CFDictionary, updatedProperties as CFDictionary)
		if saveError == errSecItemNotFound {
			/* We don't have a previous entry for the given username, keychain identifier and access group.
			 * Let’s use SecItemAdd. */
			query[kSecValueData]       = data
			query[kSecAttrIsInvisible] = kCFBooleanFalse
			query[kSecAttrAccessible]  = kSecAttrAccessibleAfterFirstUnlock
			saveError = SecItemAdd(query as CFDictionary, nil)
		}
		if saveError != errSecSuccess {
			throw Err(statusCode: saveError)
		}
		
		/* Defensive programming!
		 * Did we actually set the data correctly? */
		assert((try? getStoredData(withIdentifier: identifier, accessGroup: accessGroup, username: username)) == data)
	}
	
	public static func removeStoredData(withIdentifier identifier: String, accessGroup: String? = nil, username: String = "") throws {
		let query = try baseQuery(forIdentifier: identifier, accessGroup: accessGroup, username: username)
		
		let error = SecItemDelete(query as CFDictionary)
		switch error {
			case errSecSuccess, errSecItemNotFound/* If the item is not found, we consider the deletion has been successful. */:
				return
				
			default:
				throw Err(statusCode: error)
		}
	}
	
	public static func clearKeychain(accessGroup: String? = nil) throws {
		var query: [CFString: Any] = [kSecClass: kSecClassGenericPassword]
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
		
		let error = SecItemDelete(query as CFDictionary)
		switch error {
			case errSecSuccess, errSecItemNotFound:
				return
				
			default:
				throw Err(statusCode: error)
		}
	}
	
	/* ***************
	   MARK: - Private
	   *************** */
	
	private static func baseQuery(forIdentifier identifier: String, accessGroup: String?, username: String) throws -> [CFString: Any] {
		var res = [CFString: Any]()
		res[kSecClass] = kSecClassGenericPassword
//		res[kSecAttrGeneric] = identifier
		res[kSecAttrService] = identifier
		res[kSecAttrAccount] = username
		if #available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, *) {
			/* Make the keychain behave like iOS/watchOS/etc. on macOS.
			 * The previous behaviour is deprecated; we do not support it at all. */
			res[kSecUseDataProtectionKeychain] = kCFBooleanTrue
		}
		if let accessGroup = accessGroup {
#if os(macOS)
			guard #available(macOS 10.15, *) else {
				throw Err.accessGroupNotSupported
			}
#endif
			res[kSecAttrAccessGroup] = accessGroup
		}
		
		return res
	}
	
}
