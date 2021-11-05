import Foundation



public enum KeychainError : Error {
	
	case secError(code: OSStatus, message: String?)
	case internalError
	
}

typealias Err = KeychainError
