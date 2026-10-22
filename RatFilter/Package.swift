// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "RatFilter",
    platforms: [.macOS(.v13)],
    products: [
        .library(name: "RatFilterCore", targets: ["RatFilterCore"]),
        .library(name: "RatFilterExtension", targets: ["RatFilterExtension"]),
        .library(name: "RatMonitor", targets: ["RatMonitor"]),
        .library(name: "RatGeo", targets: ["RatGeo"]),
    ],
    targets: [
        .target(name: "RatFilterCore"),
        .target(name: "RatFilterExtension", dependencies: ["RatFilterCore"]),
        .target(name: "RatMonitor"),
        .target(name: "RatGeo"),
        .testTarget(name: "RatGeoTests", dependencies: ["RatGeo"]),
        .testTarget(name: "RatMonitorTests", dependencies: ["RatMonitor"]),
        .testTarget(name: "RatFilterCoreTests", dependencies: ["RatFilterCore"]),
    ]
)
