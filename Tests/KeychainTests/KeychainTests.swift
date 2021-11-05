import XCTest
@testable import Keychain



final class KeychainTests: XCTestCase {
	
	func testBasicStorage() throws {
		let data = Data("hello!".utf8)
		let keychainId = "fr.frostland.Keychain.test"
		XCTAssertNil(try Keychain.getStoredData(withIdentifier: keychainId))
		XCTAssertNoThrow(try Keychain.setStoredData(data, withIdentifier: keychainId))
		XCTAssertEqual(try Keychain.getStoredData(withIdentifier: keychainId), data)
		XCTAssertNoThrow(try Keychain.removeStoredData(withIdentifier: keychainId))
		XCTAssertNil(try Keychain.getStoredData(withIdentifier: keychainId))
	}
	
}
