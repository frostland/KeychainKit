// swift-tools-version:5.8
import PackageDescription


let swiftSettings: [SwiftSetting] = [.enableExperimentalFeature("StrictConcurrency")]

let package = Package(
	name: "Keychain",
	products: [.library(name: "Keychain", targets: ["Keychain"])],
	targets: [
		.target    (name: "Keychain",                                  path: "Sources", swiftSettings: swiftSettings),
		.testTarget(name: "KeychainTests", dependencies: ["Keychain"], path: "Tests",   swiftSettings: swiftSettings),
	]
)
