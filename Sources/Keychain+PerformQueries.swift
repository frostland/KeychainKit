import Foundation
import os.log
import Security



public extension Keychain {
	
	/**
	 Perform the given query and returns the results.
	 
	 If the results are not of the expected type we throw the ``KeychainError.unexpectedResultType``.
	 
	 It is highly recommended to have `kSecReturnAttributes` set to `true`.
	 
	 - Note: If you set all `kSecReturn*` parameters to `false`,
	  you will probably receive the ``KeychainError.invalidResponseFromSecurityFramework`` error,
	  which is thrown when the call the Security framework function does not return an error but returns `nil`. */
	static func performSearch<SearchResult>(_ query: [CFString: Any]) throws -> SearchResult? {
		var searchResult: CFTypeRef?
		let error = SecItemCopyMatching(query as CFDictionary, &searchResult)
		switch error {
			case errSecSuccess:
				guard let searchResult else {
					/* In theory if SecItemCopyMatching does not return an error, the search result should not be nil.
					 * If all `kSecReturn*` parameters are `false` it might though, but we document this edge case. */
					throw Err.invalidResponseFromSecurityFramework
				}
				guard let res = searchResult as? SearchResult else {
					throw Err.unexpectedResultType
				}
				return res
				
			case errSecItemNotFound:
				return nil
				
			default:
				throw Err(statusCode: error)
		}
	}
	
	static func performDelete(_ query: [CFString: Any]) throws {
		let error = SecItemDelete(query as CFDictionary)
		switch error {
			case errSecSuccess, errSecItemNotFound:
				return
				
			default:
				throw Err(statusCode: error)
		}
	}
	
}
