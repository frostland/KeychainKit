// swift-tools-version:5.5
import PackageDescription


let package = Package(
	name: "Keychain",
	products: [.library(name: "Keychain", targets: ["Keychain"])],
	targets: [
		.target(name: "Keychain", path: "Sources"),
		.testTarget(name: "KeychainTests", dependencies: ["Keychain"], path: "Tests")
	]
)
