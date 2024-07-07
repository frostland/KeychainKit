import XCTest
@testable import Keychain



final class KeychainTests: XCTestCase {
	
	func testBasicStorage() throws {
		let data = Data("hello!".utf8)
		let keychainID = "fr.frostland.Keychain.testBasicStorage"
		XCTAssertNil(try Keychain.getStoredData(withIdentifier: keychainID))
		XCTAssertNoThrow(try Keychain.setStoredData(data, withIdentifier: keychainID))
		XCTAssertEqual(try Keychain.getStoredData(withIdentifier: keychainID), data)
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
		let accessGroup = "DVL8GW97S8.fr.frostland.KeychainTestsHost.shared"
		let keychainID = "fr.frostland.Keychain.testBasicStorageAccessGroup"
		XCTAssertNil(try Keychain.getStoredData(withIdentifier: keychainID, accessGroup: accessGroup))
		XCTAssertNoThrow(try Keychain.setStoredData(data, withIdentifier: keychainID, accessGroup: accessGroup))
		XCTAssertEqual(try Keychain.getStoredData(withIdentifier: keychainID, accessGroup: accessGroup), data)
		XCTAssertNoThrow(try Keychain.removeStoredData(withIdentifier: keychainID, accessGroup: accessGroup))
		XCTAssertNil(try Keychain.getStoredData(withIdentifier: keychainID, accessGroup: accessGroup))
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
