import Foundation



public enum KeychainError : Error {
	
	/* On macOS <10.15, the access group will be silently ignored (AFAIK; not actually tested).
	 * Instead of silently doing something unexpected, we throw an actual error. */
	case accessGroupNotSupported
	/* On macOS <10,15, the kSecUseDataProtectionKeychain property is not available.
	 * Clearing the whole keychain does not make sense (and would be dangerous if it worked, which I doubt). */
	case clearingKeychainOnNonSandboxedEnvironment
	
	case secError(code: OSStatus, message: String?)
	case invalidResponseFromSecurityFramework
	case internalError
	
	public var isProtectedDataUnavailableError: Bool {
		if case .secError(errSecInteractionNotAllowed, _) = self {
			return true
		}
		return false
	}
	
}

typealias Err = KeychainError
