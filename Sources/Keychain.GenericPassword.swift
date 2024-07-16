import Foundation
import os.log
import Security



public extension Keychain {
	
	struct GenericPassword {
		
		public static nonisolated(unsafe) let securityClass: CFString = kSecClassGenericPassword
		
		/**
		 The attributes in the generic password entry.
		 
		 You should rarely have to use this property directly.
		 Instead you should use the conveniences that access/modify it. */
		public var attributes: [CFString: Any]
		public var attributesNoClass: [CFString: Any] {
			var ret = attributes
			ret.removeValue(forKey: kSecClass)
			return ret
		}
		
		public init(attributes: [CFString: Any]) {
			if attributes[kSecClass] as? String != kSecClassGenericPassword as String {
				os_log("Initing a GenericPassword with attributes containing a value for the kSecClass attribute different than kSecClassGenericPassword (got %@).", log: logger, type: .error, String(describing: attributes[kSecClass]))
			}
			self.attributes = attributes
		}
		
		public init(attributesNoClass: [CFString: Any]) {
			self.attributes = attributesNoClass
			attributes[kSecClass] = kSecClassGenericPassword
		}
		
	}
	
}


public extension Keychain.GenericPassword {
	
	static func clearAll(in accessGroup: String? = nil) throws {
		try Keychain.clearAll(ofClass: Self.securityClass, in: accessGroup)
	}
	
	static func fetchAllMatchingFromKeychain(query: Keychain.GenericPassword, retrieveData: Bool, retrieveRef: Bool = false, retrievePersistentRef: Bool = false) throws -> [Keychain.GenericPassword] {
		var query = query.attributes
		query[kSecMatchLimit]          = kSecMatchLimitAll
		query[kSecClass]               = kSecClassGenericPassword
		query[kSecReturnAttributes]    = kCFBooleanTrue
		query[kSecReturnRef]           = (retrieveRef           ? kCFBooleanTrue : kCFBooleanFalse)
		query[kSecReturnData]          = (retrieveData          ? kCFBooleanTrue : kCFBooleanFalse)
		query[kSecReturnPersistentRef] = (retrievePersistentRef ? kCFBooleanTrue : kCFBooleanFalse)
		guard let results: [[CFString: Any]] = try Keychain.performSearch(query) else {
			return []
		}
		return results.map(Keychain.GenericPassword.init(attributesNoClass:))
	}
	
	/**
	 If more than one is matching, the ``KeychainError.multipleMatches`` error is thrown.
	 If nothing matches `nil` is returned. */
	static func fetchOnlyMatchingFromKeychain(query: Keychain.GenericPassword, retrieveValue: Bool, retrieveRef: Bool = false, retrievePersistentRef: Bool = false) throws -> Keychain.GenericPassword? {
		var query = query.attributes
		query[kSecMatchLimit]          = 2
		query[kSecClass]               = kSecClassGenericPassword
		query[kSecReturnAttributes]    = kCFBooleanTrue
		query[kSecReturnRef]           = (retrieveRef           ? kCFBooleanTrue : kCFBooleanFalse)
		query[kSecReturnData]          = (retrieveValue         ? kCFBooleanTrue : kCFBooleanFalse)
		query[kSecReturnPersistentRef] = (retrievePersistentRef ? kCFBooleanTrue : kCFBooleanFalse)
		guard let results: [[CFString: Any]] = try Keychain.performSearch(query), let result = results.first else {
			return nil
		}
		guard results.count == 1 else {
			throw Err.multipleMatches
		}
		return .init(attributesNoClass: result)
	}
	
	init(service: String? = nil, account: String? = nil, accessGroup: String? = nil, synchronizable: Bool? = nil, generic: Data? = nil, value: Data? = nil) {
		self.init(attributes: [
			kSecClass: kSecClassGenericPassword
		])
		if let service        {self.service        = service}
		if let account        {self.account        = account}
		if let accessGroup    {self.accessGroup    = accessGroup}
		if let synchronizable {self.synchronizable = synchronizable}
		if let generic        {self.generic        = generic}
		if let value          {self.value          = value}
	}
	
	init(primaryKeyOf otherPassword: Keychain.GenericPassword) {
		self.init(service: otherPassword.service, account: otherPassword.account, accessGroup: otherPassword.accessGroup, synchronizable: otherPassword.synchronizable)
	}
	
	func upsertInKeychain(updatedAttributes: Keychain.GenericPassword) throws {
		do {
			/* AFAIK the Security framework does not support upsert, so we have to simulate it.
			 * This is prone to race conditions; I know.
			 * That being said, the only issue would be for a matching item to be inserted before we get the chance to execute the catch block,
			 *  in which case we’ll get a duplicated item error anyways, so it’s not a big deal.
			 *
			 * We try updating first.
			 * We could probably have tried the insertion first instead, but we had to chose something… */
			try Keychain.performUpdate(of: attributes, updatedAttributes: updatedAttributes.attributesNoClass)
		} catch let err as KeychainError where err.isItemNotFoundError {
			var newEntryAttributes = attributes
			for (k, v) in updatedAttributes.attributesNoClass {
				newEntryAttributes[k] = v
			}
			try Keychain.performInsert(attributes: newEntryAttributes)
		}
	}
	
	func deleteFromKeychain() throws {
		try Keychain.performDelete(attributes)
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
	
	/* No convenience access for kSecAttrAccess (macOS only, softly deprecated (SecKeychain only)) */
	
	/* Primary key:
	 * - kSecAttrService
	 * - kSecAttrAccount
	 * - kSecAttrAccessGroup
	 * - kSecAttrSynchronizable */
	
	var value: Data? {
		get {typedAttribute(for: kSecValueData)}
		set {attributes[kSecValueData] = newValue as CFData?}
	}
	
	var ref: SecKeychainItem? {
		get {typedAttribute(for: kSecValueRef)}
		set {attributes[kSecValueRef] = newValue}
	}
	
	var persistentRef: Data? {
		get {typedAttribute(for: kSecValuePersistentRef)}
		set {attributes[kSecValuePersistentRef] = newValue as CFData?}
	}
	
	/** Access to `kSecAttrSynchronizable`. */
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
			if let newValue {attributes[kSecAttrSynchronizable] = newValue as CFBoolean}
			else            {attributes[kSecAttrSynchronizable] = kSecAttrSynchronizableAny}
		}
	}
	
	/** Access to `kSecAttrAccessGroup`. */
	var accessGroup: String? {
		get {typedAttribute(for: kSecAttrAccessGroup)}
		set {attributes[kSecAttrAccessGroup] = newValue as CFString?}
	}
	
	/** Access to `kSecAttrAccessControl`. */
	var accessControl: SecAccessControl? {
		get {typedAttribute(for: kSecAttrAccessControl)}
		set {attributes[kSecAttrAccessControl] = newValue}
	}
	
	/** Access to `kSecAttrAccount`. */
	var account: String? {
		get {typedAttribute(for: kSecAttrAccount)}
		set {attributes[kSecAttrAccount] = newValue as CFString?}
	}
	
	/** Access to `kSecAttrService`. */
	var service: String? {
		get {typedAttribute(for: kSecAttrService)}
		set {attributes[kSecAttrService] = newValue as CFString?}
	}
	
	/** Access to `kSecAttrGeneric`. */
	var generic: Data? {
		get {typedAttribute(for: kSecAttrGeneric)}
		set {attributes[kSecAttrGeneric] = newValue as CFData?}
	}
	
	/**
	 Access to `kSecAttrAccessible`.
	 
	 Type should technically be an enum, but Security does not have it, so I ain’t gonna do it.
	 Possible values:
	 - `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly`
	 - `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`
	 - `kSecAttrAccessibleWhenUnlocked`
	 - `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`
	 - `kSecAttrAccessibleAfterFirstUnlock`
	 - (deprecated) `kSecAttrAccessibleAlwaysThisDeviceOnly`
	 - (deprecated) `kSecAttrAccessibleAlways` */
	var accessibility: CFString? {
		get {typedAttribute(for: kSecAttrAccessible)}
		set {attributes[kSecAttrAccessible] = newValue}
	}
	
	/** Access to `kSecAttrCreationDate`. */
	var creationDate: Date? {
		typedAttribute(for: kSecAttrCreationDate)
	}
	
	/** Access to `kSecAttrModificationDate`. */
	var modificationDate: Date? {
		typedAttribute(for: kSecAttrModificationDate)
	}
	
	/** Access to `kSecAttrDescription` (user-visible, non-user-editable). */
	var description: String? {
		get {typedAttribute(for: kSecAttrDescription)}
		set {attributes[kSecAttrDescription] = newValue as CFString?}
	}
	
	/** Access to `kSecAttrComment` (user-visible and user-editable). */
	var comment: String? {
		get {typedAttribute(for: kSecAttrComment)}
		set {attributes[kSecAttrComment] = newValue as CFString?}
	}
	
	/** Access to `kSecAttrCreator` (this is a FourCC). */
	var creator: UInt32? {
		get {typedAttribute(for: kSecAttrCreator)}
		set {attributes[kSecAttrCreator] = newValue as CFNumber?}
	}
	
	/** Access to `kSecAttrType` (this is a FourCC). */
	var type: UInt32? {
		get {typedAttribute(for: kSecAttrType)}
		set {attributes[kSecAttrType] = newValue as CFNumber?}
	}
	
	/** Access to `kSecAttrLabel` (user-visible, non-user-editable). */
	var label: String? {
		get {typedAttribute(for: kSecAttrLabel)}
		set {attributes[kSecAttrLabel] = newValue as CFString?}
	}
	
	/**
	 Access to `kSecAttrIsInvisible`.
	 
	 If the value is `nil`, the item is not invisible.
	 We left a nullable value to be able to update entries in the keychain w/o touching the invisibility attribute. */
	var isInvisible: Bool? {
		get {typedAttribute(for: kSecAttrIsInvisible)}
		set {attributes[kSecAttrIsInvisible] = newValue as CFBoolean?}
	}
	
	/**
	 Access to `kSecAttrIsNegative`.
	 
	 If the value is `nil`, the item is not negative.
	 We left a nullable value to be able to update entries in the keychain w/o touching the negativity attribute. */
	var isNegative: Bool? {
		get {typedAttribute(for: kSecAttrIsNegative)}
		set {attributes[kSecAttrIsNegative] = newValue as CFBoolean?}
	}
	
}
