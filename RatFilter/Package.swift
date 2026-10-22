// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "RatFilter",
    platforms: [.macOS(.v13)],
    products: [
        .library(name: "RatFilterCore", targets: ["RatFilterCore"]),
        .library(name: "RatFilterExtension", targets: ["RatFilterExtension"]),
    ],
    targets: [
        .target(name: "RatFilterCore"),
        .target(name: "RatFilterExtension", dependencies: ["RatFilterCore"]),
        .testTarget(name: "RatFilterCoreTests", dependencies: ["RatFilterCore"]),
    ]
)
