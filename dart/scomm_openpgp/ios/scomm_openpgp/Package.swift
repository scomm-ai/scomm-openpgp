// swift-tools-version: 5.9
import PackageDescription

let package = Package(
  name: "scomm_openpgp",
  platforms: [
    .iOS("14.0")
  ],
  products: [
    // The Flutter tooling requires the library product name to be the
    // dasherized plugin name.
    .library(name: "scomm-openpgp", targets: ["scomm_openpgp"])
  ],
  targets: [
    .target(
      name: "scomm_openpgp",
      dependencies: ["libscomm_openpgp"]
    ),
    // Prebuilt by CI (.github/workflows/prebuilt.yml). It holds dynamic
    // frameworks, so Xcode embeds and signs it and users can relink the LGPL library.
    .binaryTarget(
      name: "libscomm_openpgp",
      path: "Frameworks/libscomm_openpgp.xcframework"
    ),
  ]
)
