import Foundation



public enum KeychainError : Error {
	
	/**
	 On macOS &lt;10.15, the access group will be silently ignored (AFAIK; not actually tested).
	 Instead of silently doing something unexpected, we throw an actual error. */
	case accessGroupNotSupported
	/**
	 On macOS &lt;10,15, the `kSecUseDataProtectionKeychain` property is not available.
	 Clearing the whole keychain does not make sense (and would be dangerous if it worked, which I doubt). */
	case clearingKeychainOnNonSandboxedEnvironment
	
	case multipleMatches
	
	case invalidResponseFromSecurityFramework
	case unexpectedResultType
	
	case secError(code: OSStatus, message: String?)
	
	internal init(statusCode: OSStatus) {
#if os(macOS)
		self = .secError(code: statusCode, message: SecCopyErrorMessageString(statusCode, nil/* reserved for future use */) as String?)
#else
		self = .secError(code: statusCode, message: nil)
#endif
	}
	
	public var isProtectedDataUnavailableError: Bool {
		if case .secError(errSecInteractionNotAllowed, _) = self {
			return true
		}
		return false
	}
	
}

typealias Err = KeychainError
