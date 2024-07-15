import Foundation
import os.log
import Security



public extension Keychain {
	
	/**
	 Performs the given search and returns the results.
	 
	 The results are **always** returned in a dictionary.
	 This happens because we modify the query to always ask for the attributes.
	 
	 Always adding the attributes has also the side effect that
	  if no return values are requested in the original query,
	  SecItemCopyMatching will not return nil (because the attributes will be requested). */
	static func performSearch(_ query: [CFString: Any]) throws -> [CFString: Any]? {
		var query = query
		if !((query[kSecReturnAttributes] as? Bool) ?? false) {
			os_log("Modifying keychain search query to include attributes in the results.", log: logger, type: .info)
			query[kSecReturnAttributes] = true
		}
		
		var searchResult: CFTypeRef?
		let error = SecItemCopyMatching(query as CFDictionary, &searchResult)
		switch error {
			case errSecSuccess:
				if let dictionary = searchResult as? [CFString: Any] {
					return dictionary
				} else {
					/* In theory if SecItemCopyMatching does not return an error, the search result should not be nil. */
					throw Err.invalidResponseFromSecurityFramework
				}
				
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
