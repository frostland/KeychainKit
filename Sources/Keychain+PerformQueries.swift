import Foundation
import os.log
import Security



public extension Keychain {
	
	/**
	 Perform the given query and returns the results.
	 
	 If the results are not of the expected type we throw the ``KeychainError.unexpectedResultType``.
	 
	 If no values match the given query, the function will _not_ throw an error but will return `nil` instead.
	 
	 - Note: If you set all `kSecReturn*` parameters to `false`,
	  you will probably receive the ``KeychainError.invalidResponseFromSecurityFramework`` error,
	  which is thrown when the call the Security framework function does not return an error but set the results to `nil`. */
	static func performSearch<SearchResult>(_ query: [CFString: Any]) throws -> SearchResult? {
		var searchResult: CFTypeRef?
		let query = try fixQueryForMacOS(query)
		let error = SecItemCopyMatching(query as CFDictionary, &searchResult)
		switch error {
			case errSecSuccess:
				guard let searchResult else {
					/* In theory if SecItemCopyMatching does not return an error, the search result should not be nil.
					 * If all `kSecReturn*` parameters are `false` it might though, but we document this edge case.
					 * It’s still better than returning a double-optional IMHO. */
					os_log("Got a nil search result. Did you forget to set a `kSecReturn*` key to `true`?", log: logger, type: .default)
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
	
	/** Insert the given attributes in the keychain and ignore the results. */
	static func performInsert(attributes: [CFString: Any]) throws {
		let query = try fixQueryForMacOS(attributes)
		let error = SecItemAdd(query as CFDictionary, nil)
		guard error == errSecSuccess else {
			throw Err(statusCode: error)
		}
	}
	
	/**
	 Insert the given attributes in the keychain and return the results.
	 The attributes are expected to have at least one `kSecReturn*` key set to `true` as the results of the insertion are returned.
	 
	 The results are returned under the form of a `Result`.
	 We do this because we only want to fail if the actual insertion failed, not if parsing the results failed.
	 
	 If no `kSecReturn*` key is set to `true`, the returned value will be most likely be a failure whose error is a ``KeychainError.invalidResponseFromSecurityFramework``. */
	static func performInsert<InsertionResult>(attributes: [CFString: Any]) throws -> Result<InsertionResult, Error> {
		var insertionResult: CFTypeRef?
		let query = try fixQueryForMacOS(attributes)
		let error = SecItemAdd(query as CFDictionary, &insertionResult)
		guard error == errSecSuccess else {
			throw Err(statusCode: error)
		}
		/* The insertion succeeded: we wrap any error decoding the result in a Result. */
		return Result{
			guard let insertionResult else {
				/* In this case the error is most likely on the client, not on the Security framework.
				 * The client most likely forgot to set any `kSecReturn*` to `true`. */
				os_log("Got a nil insertion result. Did you forget to set a `kSecReturn*` key to `true`?", log: logger, type: .default)
				throw Err.invalidResponseFromSecurityFramework
			}
			guard let res = insertionResult as? InsertionResult else {
				throw Err.unexpectedResultType
			}
			return res
		}
	}
	
	/**
	 Update the password matching the given query with the given attributes.
	 
	 This function throws an error if the query does not match anything in the keychain.
	 You can use ``KeychainError.isItemNotFoundError`` to check for this error in particular. */
	static func performUpdate(of query: [CFString: Any], updatedAttributes: [CFString: Any]) throws {
		let query = try fixQueryForMacOS(query)
		let error = SecItemUpdate(query as CFDictionary, updatedAttributes as CFDictionary)
		guard error == errSecSuccess else {
			throw Err(statusCode: error)
		}
	}
	
	static func performDelete(_ query: [CFString: Any]) throws {
		let query = try fixQueryForMacOS(query)
		let error = SecItemDelete(query as CFDictionary)
		switch error {
			case errSecSuccess, errSecItemNotFound:
				return
				
			default:
				throw Err(statusCode: error)
		}
	}
	
	private static func fixQueryForMacOS(_ query: [CFString: Any]) throws -> [CFString: Any] {
		var query = query
		if #available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, *) {
			/* Make the keychain behave like iOS/watchOS/etc. on macOS.
			 * The previous behaviour is soft-deprecated; we do not support it at all. */
			query[kSecUseDataProtectionKeychain] = kCFBooleanTrue
		}
#if os(macOS)
		if #unavailable(macOS 10.15), query[kSecAttrAccessGroup] != nil {
			throw Err.accessGroupNotSupported
		}
#endif
		return query
	}
	
}
