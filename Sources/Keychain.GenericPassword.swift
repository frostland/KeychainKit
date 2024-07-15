import Foundation
import os.log
import Security



public extension Keychain {
	
	struct GenericPassword {
		
		public static nonisolated(unsafe) let securityClass: CFString = kSecClassGenericPassword
		public var attributes: [CFString: Any]
		
	}
	
}


public extension Keychain.GenericPassword {
	
	static func clearAll(in accessGroup: String? = nil) throws {
		try Keychain.clearAll(ofClass: Self.securityClass, in: accessGroup)
	}
	
}


public extension Keychain.GenericPassword {
	
	func typedAttribute<T>(for key: CFString) -> T? {
		guard let value = attributes[key] else {
			return nil
		}
		guard let val = value as? T else {
			os_log("Invalid value (not a ${public}@) for %{public}@ in a generic password.", log: logger, type: .default, String(describing: T.self), key as String)
			return nil
		}
		return val
	}
	
}


public extension Keychain.GenericPassword {
	
	var synchronizable: Bool? {
		get {
			switch attributes[kSecAttrSynchronizable] {
				case let v as Bool where  v: return true
				case let v as Bool where !v: return false
				case nil:                                                                  return nil
				case let str as String where str == (kSecAttrSynchronizableAny as String): return nil
				default:
					os_log("Invalid value for kSecAttrSynchronizable in a generic password.", log: logger, type: .default)
					return nil
			}
		}
		set {
			/* We set the value to kSecAttrSynchronizableAny if synchronizable is set to nil as it’s most likely what the client wants
			 *  (use the attributes in a query to search both synchronizable and non-synchronizable elements).
			 * If the goal is to get the attributes to update an element, a concrete value would probably be set… */
			if let newValue {attributes[kSecAttrSynchronizable] = newValue}
			else            {attributes[kSecAttrSynchronizable] = kSecAttrSynchronizableAny}
		}
	}
	
	var accessGroup: String? {
		get {typedAttribute(for: kSecAttrAccessGroup)}
		set {attributes[kSecAttrAccessGroup] = newValue as CFString?}
	}
	
	var account: String? {
		get {typedAttribute(for: kSecAttrAccount)}
		set {attributes[kSecAttrAccount] = newValue as CFString?}
	}
	
	var service: String? {
		get {typedAttribute(for: kSecAttrAccount)}
		set {attributes[kSecAttrService] = newValue as CFString?}
	}
	
	var generic: Data? {
		get {typedAttribute(for: kSecAttrAccount)}
		set {attributes[kSecAttrGeneric] = newValue as CFData?}
	}
	
	/* Type should technically be an enum, but Security does not have it, so I ain’t gonna do it.
	 * - kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly
	 * - kSecAttrAccessibleWhenUnlockedThisDeviceOnly
	 * - kSecAttrAccessibleWhenUnlocked
	 * - kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
	 * - kSecAttrAccessibleAfterFirstUnlock
	 * - (deprecated) kSecAttrAccessibleAlwaysThisDeviceOnly
	 * - (deprecated) kSecAttrAccessibleAlways */
	var accessibility: CFString? {
		get {typedAttribute(for: kSecAttrAccessible)}
		set {attributes[kSecAttrAccessible] = newValue}
	}
	
	/* No convenience access for:
	 * - kSecAttrAccess (macOS only, softly deprecated (SecKeychain only))
	 * - kSecAttrAccessControl */
	
}
