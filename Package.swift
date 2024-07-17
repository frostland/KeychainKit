// swift-tools-version:5.10
import PackageDescription


let swiftSettings: [SwiftSetting] = [.enableExperimentalFeature("StrictConcurrency")]

let package = Package(
	name: "KeychainKit",
	/* The name of the library is KeychainKit instead of just Keychain because we have an enum called Keychain in the module and Swift does not deal with this correctly.
	 * Once <https://github.com/swiftlang/swift/issues/56573> is fixed (if ever), we’ll probably revert the name back to just “Keychain”. */
	products: [.library(name: "KeychainKit", targets: ["KeychainKit"])],
	targets: [
		.target    (name: "KeychainKit",                                     path: "Sources", swiftSettings: swiftSettings),
		.testTarget(name: "KeychainKitTests", dependencies: ["KeychainKit"], path: "Tests",   swiftSettings: swiftSettings),
	]
)
