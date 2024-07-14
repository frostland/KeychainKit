import Foundation
import Security
import XCTest

/* testable import to get the “status code” init of KeychainError, but otherwise unneeded. */
@testable import KeychainKit



final class SecurityTests : XCTestCase {
	
	override func setUp() async throws {
		try Keychain.clearKeychain()
	}
	
	func testUpdateServiceAccountGeneric() throws {
		let baseQuery: [CFString : Any] = [
			kSecClass: kSecClassGenericPassword,
			kSecUseDataProtectionKeychain: kCFBooleanTrue!,
			
			kSecAttrService: "SecTest",
			kSecAttrAccount: "Bob"
		]
		
		/* Create the entry w/ some data (42) and a generic (21). */
		XCTAssertNoThrow(try secCall{
			var query = baseQuery
			query[kSecValueData] = Data([42])
			query[kSecAttrGeneric] = Data([21])
			return SecItemAdd(query as CFDictionary, nil)
		})
		
		XCTAssertNoThrow(try secCall{
			return SecItemUpdate(baseQuery as CFDictionary, [:] as CFDictionary)
		})
		
		XCTAssertNoThrow(try secCall{
			var query = baseQuery
			query[kSecAttrGeneric] = Data([21])
			return SecItemUpdate(query as CFDictionary, [:] as CFDictionary)
		})
		
		XCTAssertThrowsError(try secCall{
			var query = baseQuery
			query[kSecAttrGeneric] = Data([])
			return SecItemUpdate(query as CFDictionary, [:] as CFDictionary)
		}, "expected an error because the item does not exist", { (err: Error) in
			XCTAssertEqual(err as? KeychainError, KeychainError(statusCode: errSecItemNotFound))
		})
		
		XCTAssertNoThrow(try secCall{
			return SecItemUpdate(baseQuery as CFDictionary, [kSecAttrGeneric: Data([42])] as CFDictionary)
		})
		
		XCTAssertThrowsError(try secCall{
			var query = baseQuery
			query[kSecAttrGeneric] = Data([21])
			return SecItemUpdate(query as CFDictionary, [:] as CFDictionary)
		}, "expected an error because the item does not exist", { (err: Error) in
			XCTAssertEqual(err as? KeychainError, KeychainError(statusCode: errSecItemNotFound))
		})
	}
	
	func testEntryNoAccount() throws {
		var query: [CFString : Any] = [
			kSecClass: kSecClassGenericPassword,
			kSecUseDataProtectionKeychain: kCFBooleanTrue!,
			kSecAttrService: "SecTest",
			kSecValueData: Data([42])
		]
		XCTAssertNoThrow(try secCall{
			return SecItemAdd(query as CFDictionary, nil)
		})
		
		query[kSecAttrAccount] = "Yolo"
		XCTAssertNoThrow(try secCall{
			return SecItemAdd(query as CFDictionary, nil)
		})
		
		query[kSecAttrAccount] = ""
		XCTAssertThrowsError(try secCall{
			return SecItemAdd(query as CFDictionary, nil)
		}, "expected an error because the item already exist as not setting the account is the same as setting it to nil", { (err: Error) in
			XCTAssertEqual(err as? KeychainError, KeychainError(statusCode: errSecDuplicateItem))
		})
	}
	
}


extension KeychainError : Equatable {
	
	public static func ==(lhs: KeychainError, rhs: KeychainError) -> Bool {
		switch (lhs, rhs) {
			case (.accessGroupNotSupported,                   .accessGroupNotSupported):                   return true
			case (.clearingKeychainOnNonSandboxedEnvironment, .clearingKeychainOnNonSandboxedEnvironment): return true
			case (.secError(let c1, _),                       .secError(let c2, _)):                       return c1 == c2
			case (.invalidResponseFromSecurityFramework,      .invalidResponseFromSecurityFramework):      return true
			case (.internalError,                             .internalError):                             return true
				
			case (.accessGroupNotSupported,                   _): return false
			case (.clearingKeychainOnNonSandboxedEnvironment, _): return false
			case (.secError,                                  _): return false
			case (.invalidResponseFromSecurityFramework,      _): return false
			case (.internalError,                             _): return false
		}
	}
	
}
