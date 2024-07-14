import Foundation
import Security
import XCTest

@testable import KeychainKit



final class KeychainTests : XCTestCase {
	
	override func setUp() async throws {
		try Keychain.clearKeychain()
	}
	
	func testPerformSearch() throws {
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
		
		let ret = try XCTUnwrap(Keychain.performSearch({
			var query = baseQuery
			query[kSecReturnPersistentRef] = kCFBooleanTrue
			return query
		}()))
		XCTAssertEqual(ret.count, 1)
		XCTAssertNotNil(ret[kSecValuePersistentRef])
	}
	
	func testBasicStorage() throws {
		let data = Data("hello!".utf8)
		let accessGroup = "DVL8GW97S8.fr.frostland.KeychainTestsHost"
		let keychainID = "fr.frostland.Keychain.testBasicStorage"
		XCTAssertNil(try Keychain.getStoredData(withIdentifier: keychainID))
		XCTAssertNoThrow(try Keychain.setStoredData(data, withIdentifier: keychainID))
		XCTAssertEqual(try Keychain.getStoredData(withIdentifier: keychainID), data)
		XCTAssertEqual(try Keychain.getStoredData(withIdentifier: keychainID, accessGroup: accessGroup), data)
		XCTAssertNoThrow(try Keychain.removeStoredData(withIdentifier: keychainID))
		XCTAssertNil(try Keychain.getStoredData(withIdentifier: keychainID))
	}
	
	func testClearKeychain() throws {
		let data = Data("hello!".utf8)
		let keychainID = "fr.frostland.Keychain.testClearKeychain"
		XCTAssertNoThrow(try Keychain.setStoredData(data, withIdentifier: keychainID))
		XCTAssertNoThrow(try Keychain.clearKeychain())
		XCTAssertNil(try Keychain.getStoredData(withIdentifier: keychainID))
	}
	
	func testBasicStorageAccessGroup() throws {
		let data = Data("hello!".utf8)
		let accessGroup = "DVL8GW97S8.fr.frostland.KeychainTestsHost"
		let accessGroupShared = "DVL8GW97S8.fr.frostland.KeychainTestsHost.shared"
		let keychainID = "fr.frostland.Keychain.testBasicStorageAccessGroup"
		XCTAssertNil(try Keychain.getStoredData(withIdentifier: keychainID, accessGroup: accessGroup))
		XCTAssertNil(try Keychain.getStoredData(withIdentifier: keychainID, accessGroup: accessGroupShared))
		XCTAssertNoThrow(try Keychain.setStoredData(data, withIdentifier: keychainID, accessGroup: accessGroupShared))
		XCTAssertEqual(try Keychain.getStoredData(withIdentifier: keychainID, accessGroup: accessGroupShared), data)
		/* If the access group is not specified, all the access groups are searched.
		 * I think it is not possible to change this behavious (to search only the default one):
		 *  if this is needed, the default access group must be manually specified. */
		XCTAssertEqual(try Keychain.getStoredData(withIdentifier: keychainID), data)
		XCTAssertNil(try Keychain.getStoredData(withIdentifier: keychainID, accessGroup: accessGroup))
		XCTAssertNoThrow(try Keychain.removeStoredData(withIdentifier: keychainID, accessGroup: accessGroupShared))
		XCTAssertNil(try Keychain.getStoredData(withIdentifier: keychainID, accessGroup: accessGroupShared))
	}
	
	func testClearKeychainAccessGroup() throws {
		let data = Data("hello!".utf8)
		let accessGroup = "DVL8GW97S8.fr.frostland.KeychainTestsHost.shared"
		let keychainID = "fr.frostland.Keychain.testClearKeychainAccessGroup"
		XCTAssertNoThrow(try Keychain.setStoredData(data, withIdentifier: keychainID, accessGroup: accessGroup))
		XCTAssertNoThrow(try Keychain.clearKeychain(accessGroup: accessGroup))
		XCTAssertNil(try Keychain.getStoredData(withIdentifier: keychainID, accessGroup: accessGroup))
	}
	
}
