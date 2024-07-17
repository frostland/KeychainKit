import Foundation
import Security
import XCTest

/* testable import to get the “status code” init of KeychainError, but otherwise unneeded. */
@testable import KeychainKit



final class SecurityTests : XCTestCase {
	
	override func setUp() async throws {
		try Keychain.GenericPassword.clearAll()
	}
	
	func testUpdateServiceAccountGeneric() throws {
		let baseQuery: [CFString: Any] = [
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
		var query: [CFString: Any] = [
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
	
#if os(macOS)
	/* On non-macOS platforms retreiving the ref of a keychain item is not supported as SecKeychain does not exist.
	 * The observed behaviour is the request succeeds(!) but returns a NULL ref. */
	@available(macOS, deprecated: 10.10)
	func testFetchItemRef() throws {
		let baseQuery: [CFString: Any] = [
			kSecClass: kSecClassGenericPassword,
			kSecUseDataProtectionKeychain: kCFBooleanTrue!,
			kSecAttrService: "SecTest"
		]
		XCTAssertNoThrow(try secCall{
			var query = baseQuery
			query[kSecValueData] = Data([42])
			return SecItemAdd(query as CFDictionary, nil)
		})
		
		let ret = try secCall{
			var query = baseQuery
			query[kSecReturnRef] = kCFBooleanTrue
			return SecItemCopyMatching(query as CFDictionary, $0)
		}
		XCTAssert(CFGetTypeID(ret) == SecKeychainItemGetTypeID())
	}
#endif
	
	func testFetchItemPersistentRef() throws {
		let baseQuery: [CFString: Any] = [
			kSecClass: kSecClassGenericPassword,
			kSecUseDataProtectionKeychain: kCFBooleanTrue!,
			kSecAttrService: "SecTest"
		]
		XCTAssertNoThrow(try secCall{
			var query = baseQuery
			query[kSecValueData] = Data([42])
			return SecItemAdd(query as CFDictionary, nil)
		})
		
		let ret = try secCall{
			var query = baseQuery
			query[kSecReturnPersistentRef] = kCFBooleanTrue
			return SecItemCopyMatching(query as CFDictionary, $0)
		}
		XCTAssert(CFGetTypeID(ret) == CFDataGetTypeID())
	}
	
	func testFetchItemAttributes() throws {
		let baseQuery: [CFString: Any] = [
			kSecClass: kSecClassGenericPassword,
			kSecUseDataProtectionKeychain: kCFBooleanTrue!,
			kSecAttrService: "SecTest"
		]
		XCTAssertNoThrow(try secCall{
			var query = baseQuery
			query[kSecValueData] = Data([42])
			return SecItemAdd(query as CFDictionary, nil)
		})
		
		let ret = try secCall{
			var query = baseQuery
			query[kSecReturnAttributes] = kCFBooleanTrue
			return SecItemCopyMatching(query as CFDictionary, $0)
		}
		XCTAssert(CFGetTypeID(ret) == CFDictionaryGetTypeID())
	}
	
	func testFetchItemData() throws {
		let baseQuery: [CFString: Any] = [
			kSecClass: kSecClassGenericPassword,
			kSecUseDataProtectionKeychain: kCFBooleanTrue!,
			kSecAttrService: "SecTest"
		]
		XCTAssertNoThrow(try secCall{
			var query = baseQuery
			query[kSecValueData] = Data([42])
			return SecItemAdd(query as CFDictionary, nil)
		})
		
		let ret = try secCall{
			var query = baseQuery
			query[kSecReturnData] = kCFBooleanTrue
			return SecItemCopyMatching(query as CFDictionary, $0)
		}
		XCTAssert(CFGetTypeID(ret) == CFDataGetTypeID())
	}
	
	func testFetchItemDataAndAttributesAndPersistentRef() throws {
		let baseQuery: [CFString: Any] = [
			kSecClass: kSecClassGenericPassword,
			kSecUseDataProtectionKeychain: kCFBooleanTrue!,
			kSecAttrService: "SecTest"
		]
		XCTAssertNoThrow(try secCall{
			var query = baseQuery
			query[kSecValueData] = Data([42])
			return SecItemAdd(query as CFDictionary, nil)
		})
		
		/* Surprisingly this does not fail!
		 * It returns the attributes and the two additional keys: “v_Data” (kSecValueData) and “v_PersistentRef” (kSecValuePersistentRef). */
		let ret = try secCall{
			var query = baseQuery
			query[kSecReturnData] = kCFBooleanTrue
			query[kSecReturnAttributes] = kCFBooleanTrue
			query[kSecReturnPersistentRef] = kCFBooleanTrue
			return SecItemCopyMatching(query as CFDictionary, $0)
		}
		XCTAssert(CFGetTypeID(ret) == CFDictionaryGetTypeID())
	}
	
	func testInsertAndSearchForEmptyGeneric() throws {
		let baseQuery: [CFString: Any] = [
			kSecClass: kSecClassGenericPassword,
			kSecUseDataProtectionKeychain: kCFBooleanTrue!,
			
			kSecAttrService: "SecTest",
			kSecAttrAccount: "Bob"
		]
		
		/* Create the entry w/ some data (42) and no generic. */
		XCTAssertNoThrow(try secCall{
			var query = baseQuery
			query[kSecValueData] = Data([42])
			return SecItemAdd(query as CFDictionary, nil)
		})
		
		XCTAssertNoThrow(try secCall{
			return SecItemUpdate(baseQuery as CFDictionary, [:] as CFDictionary)
		})
		
		XCTAssertThrowsError(try secCall{
			var query = baseQuery
			query[kSecAttrGeneric] = Data([])
			return SecItemUpdate(query as CFDictionary, [:] as CFDictionary)
		}, "item does not have correct generic; the call should fail", { (err: Error) in
			XCTAssertEqual(err as? KeychainError, KeychainError(statusCode: errSecItemNotFound))
		})
		
		XCTAssertNoThrow(try secCall{
			return SecItemUpdate(baseQuery as CFDictionary, [kSecAttrGeneric: Data([])] as CFDictionary)
		})
		
		XCTAssertThrowsError(try secCall{
			var query = baseQuery
			query[kSecAttrGeneric] = Data([1])
			return SecItemUpdate(query as CFDictionary, [:] as CFDictionary)
		}, "item does not have correct generic; the call should fail", { (err: Error) in
			XCTAssertEqual(err as? KeychainError, KeychainError(statusCode: errSecItemNotFound))
		})
		
		XCTAssertNoThrow(try secCall{
			var query = baseQuery
			query[kSecAttrGeneric] = Data([])
			return SecItemUpdate(query as CFDictionary, [:] as CFDictionary)
		})
	}
	
	func testFetchItemDataAndPersistentRef() throws {
		let baseQuery: [CFString: Any] = [
			kSecClass: kSecClassGenericPassword,
			kSecUseDataProtectionKeychain: kCFBooleanTrue!,
			kSecAttrService: "SecTest"
		]
		XCTAssertNoThrow(try secCall{
			var query = baseQuery
			query[kSecValueData] = Data([42])
			return SecItemAdd(query as CFDictionary, nil)
		})
		
		/* Surprisingly some attributes are returned anyway. */
		let ret = try secCall{
			var query = baseQuery
			query[kSecReturnData] = kCFBooleanTrue
			query[kSecReturnAttributes] = kCFBooleanFalse
			query[kSecReturnPersistentRef] = kCFBooleanTrue
			return SecItemCopyMatching(query as CFDictionary, $0)
		}
		XCTAssert(CFGetTypeID(ret) == CFDictionaryGetTypeID())
	}
	
	func testFetchTwoElements() throws {
		let baseQuery: [CFString: Any] = [
			kSecClass: kSecClassGenericPassword,
			kSecUseDataProtectionKeychain: kCFBooleanTrue!,
			kSecAttrService: "SecTest"
		]
		
		XCTAssertNoThrow(try secCall{
			var query = baseQuery
			query[kSecAttrAccount] = "yolo1"
			query[kSecValueData] = Data([42])
			return SecItemAdd(query as CFDictionary, nil)
		})
		let ret1 = try secCall{
			var query = baseQuery
			query[kSecMatchLimit] = kSecMatchLimitAll
			query[kSecReturnData] = kCFBooleanTrue
			query[kSecReturnAttributes] = kCFBooleanTrue
			return SecItemCopyMatching(query as CFDictionary, $0)
		}
		XCTAssert(CFGetTypeID(ret1) == CFArrayGetTypeID())
		
		XCTAssertNoThrow(try secCall{
			var query = baseQuery
			query[kSecAttrAccount] = "yolo2"
			query[kSecValueData] = Data([42])
			return SecItemAdd(query as CFDictionary, nil)
		})
		let ret2 = try secCall{
			var query = baseQuery
			query[kSecMatchLimit] = kSecMatchLimitAll
			query[kSecReturnData] = kCFBooleanTrue
			query[kSecReturnAttributes] = kCFBooleanTrue
			return SecItemCopyMatching(query as CFDictionary, $0)
		}
		XCTAssert(CFGetTypeID(ret2) == CFArrayGetTypeID())
		
		/* Returns the “first one” matching (which is undefined AFAIK). */
		let ret3 = try secCall{
			var query = baseQuery
			query[kSecMatchLimit] = kSecMatchLimitOne
			query[kSecReturnData] = kCFBooleanTrue
			query[kSecReturnAttributes] = kCFBooleanTrue
			return SecItemCopyMatching(query as CFDictionary, $0)
		}
		XCTAssert(CFGetTypeID(ret3) == CFDictionaryGetTypeID())
	}
	
}


extension KeychainError : Equatable {
	
	public static func ==(lhs: KeychainError, rhs: KeychainError) -> Bool {
		switch (lhs, rhs) {
			case (.accessGroupNotSupported,                   .accessGroupNotSupported):                   return true
			case (.clearingKeychainOnNonSandboxedEnvironment, .clearingKeychainOnNonSandboxedEnvironment): return true
			case (.secError(let c1, _),                       .secError(let c2, _)):                       return c1 == c2
			case (.invalidResponseFromSecurityFramework,      .invalidResponseFromSecurityFramework):      return true
			case (.multipleMatches,                           .multipleMatches):                           return true
			case (.unexpectedResultType,                      .unexpectedResultType):                      return true
			case (.localItemOutOfDate,                        .localItemOutOfDate):                        return true
				
			case (.accessGroupNotSupported,                   _): return false
			case (.clearingKeychainOnNonSandboxedEnvironment, _): return false
			case (.secError,                                  _): return false
			case (.invalidResponseFromSecurityFramework,      _): return false
			case (.multipleMatches,                           _): return false
			case (.unexpectedResultType,                      _): return false
			case (.localItemOutOfDate,                        _): return false
		}
	}
	
}
