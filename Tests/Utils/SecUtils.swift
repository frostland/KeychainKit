/* Adapted from <https://developer.apple.com/forums/thread/710961>.
 * Looked interesting but we don’t use it after all. */

import Foundation
import Security

/* testable import to get the “status code” init of KeychainError. */
@testable import KeychainKit



/**
 Calls a Security framework function, throwing if it returns an error.

 For example, the `SecACLRemove` function has a signature like this:
 ```
 func SecACLRemove(…) -> OSStatus
 ```

 and so you call it like this:
 ```
 try secCall{ SecACLRemove(acl) }
 ```

 - Parameter body: A function that returns an `OSStatus` value.
 - Throws: If `body` returns anything other than `errSecSuccess`. */
func secCall(_ body: () -> OSStatus) throws {
	let err = body()
	guard err == errSecSuccess else {
//		throw NSError(domain: NSOSStatusErrorDomain, code: Int(err), userInfo: nil)
		throw KeychainError(statusCode: err)
	}
}


/**
 Calls a Security framework function that returns an error and a value indirectly.

 For example, the `SecItemCopyMatching` function has a signature like this:
 ```
 func SecItemCopyMatching(…, _ result: UnsafeMutablePointer<CFTypeRef?>?) -> OSStatus
 ```

 and so you call it like this:
 ```
 let keys = try secCall{ SecItemCopyMatching([
     kSecClass: kSecClassKey,
     kSecMatchLimit: kSecMatchLimitAll,
     kSecReturnRef: true,
 ] as NSDictionary, $0) }
 ```

 - Parameter body: A function that returns an `OSStatus` value and takes a ‘out’ pointer to return the result indirectly.
 - Throws: If `body` returns anything other than `errSecSuccess`.
 - Returns: The value returned indirectly by the function. */
func secCall<Result>(_ body: (_ resultPtr: UnsafeMutablePointer<Result?>) -> OSStatus) throws -> Result {
	var result: Result? = nil
	let err = body(&result)
	guard err == errSecSuccess else {
//		throw NSError(domain: NSOSStatusErrorDomain, code: Int(err), userInfo: nil)
		throw KeychainError(statusCode: err)
	}
	guard let result else {
		throw KeychainError.invalidResponseFromSecurityFramework
	}
	return result
}


/**
 Calls a Security framework function that returns `nil` on error.

 For example, the `SecKeyCopyPublicKey` function has a signature like this:
 ```
 func SecKeyCopyPublicKey(…) -> SecKey?
 ```

 and so you call it like this:
 ```
 let publicKey = try secCall{ SecKeyCopyPublicKey(privateKey) }
 ```

 - Parameters:
   - code: An `OSStatus` value to throw if there’s an error; defaults to `errSecParam`.
   - body: A function that returns a value, or `nil` if there’s an error.
 - Throws: If `body` returns `nil`.
 - Returns: On success, the non-`nil` value returned by `body`. */
func secCall<Result>(_ code: Int32 = errSecParam, _ body: () -> Result?) throws -> Result {
	guard let result = body() else {
//		throw NSError(domain: NSOSStatusErrorDomain, code: code, userInfo: nil)
		throw KeychainError(statusCode: code)
	}
	return result
}


/**
 Calls a Security framework function that returns `nil` on error along with a `CFError` indirectly.

 For example, the `SecKeyCreateDecryptedData` function has a signature like this:
 ```
 func SecKeyCreateDecryptedData(…, _ error: UnsafeMutablePointer<Unmanaged<CFError>?>?) -> CFData?
 ```

 and so you call it like this:
 ```
 let plainText = try secCall{ SecKeyCreateDecryptedData(privateKey, .rsaEncryptionPKCS1, cypherText, $0) }
 ```

 - Parameter body: A function that returns a value, which returns `nil` if there’s an error and, in that case, places a `CFError` value in the ‘out’ parameter.
 - Throws: If `body` returns `nil`.
 - Returns: On success, the non-`nil` value returned by `body`. */
func secCall<Result>(_ body: (_ resultPtr: UnsafeMutablePointer<Unmanaged<CFError>?>) -> Result?) throws -> Result {
	var errorQ: Unmanaged<CFError>? = nil
	guard let result = body(&errorQ) else {
		guard let errorQ else {
			throw KeychainError.invalidResponseFromSecurityFramework
		}
		throw errorQ.takeRetainedValue() as Error
	}
	return result
}


/**
 Calls a Security framework function that returns false on error along with a `CFError` indirectly.

 For example, the `SecKeyVerifySignature` function has a signature like this:
 ```
 func SecKeyVerifySignature(…, _ error: UnsafeMutablePointer<Unmanaged<CFError>?>?) -> Bool
 ```

 and so you call it like this:
 ```
 try secCall{ SecKeyVerifySignature(publicKey, .ecdsaSignatureMessageX962SHA1, signedData, signature, $0) }
 ```

 - Parameter body: A function that returns a false if there’s an error and, in that case, places a `CFError` value in the ‘out’ parameter.
 - Throws: If `body` returns false. */
func secCall(_ body: (_ resultPtr: UnsafeMutablePointer<Unmanaged<CFError>?>) -> Bool) throws {
	var errorQ: Unmanaged<CFError>? = nil
	guard body(&errorQ) else {
		guard let errorQ else {
			throw KeychainError.invalidResponseFromSecurityFramework
		}
		throw errorQ.takeRetainedValue() as Error
	}
}
