import Foundation



public enum KeychainError : Error {
	
	case secError(code: OSStatus, message: String?)
	case invalidResponseFromSecurityFramework
	case internalError
	
}

typealias Err = KeychainError
