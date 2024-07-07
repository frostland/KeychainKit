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
	
}
