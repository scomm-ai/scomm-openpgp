# Prebuilt `scomm_openpgp` libraries

CI builds these cdylibs and commits them here. App builds copy or download the
file for the host triple. They do not compile OpenSSL.

iOS is not a loose dylib. CI wraps the device and simulator slices into
`dart/scomm_openpgp/ios/scomm_openpgp/Frameworks/libscomm_openpgp.xcframework`.

| Triple | File |
| --- | --- |
| `x86_64-pc-windows-msvc` | `scomm_openpgp.dll` |
| `i686-pc-windows-msvc` | `scomm_openpgp.dll` |
| `aarch64-pc-windows-msvc` | `scomm_openpgp.dll` |
| `x86_64-unknown-linux-gnu` | `libscomm_openpgp.so` |
| `i686-unknown-linux-gnu` | `libscomm_openpgp.so` |
| `aarch64-unknown-linux-gnu` | `libscomm_openpgp.so` |
| `x86_64-apple-darwin` | `libscomm_openpgp.dylib` |
| `aarch64-apple-darwin` | `libscomm_openpgp.dylib` |
| `x86_64-linux-android` | `libscomm_openpgp.so` |
| `i686-linux-android` | `libscomm_openpgp.so` |
| `aarch64-linux-android` | `libscomm_openpgp.so` |
| `armv7-linux-androideabi` | `libscomm_openpgp.so` |
| `aarch64-apple-ios` | `dart/scomm_openpgp/ios/scomm_openpgp/Frameworks/libscomm_openpgp.xcframework` (device slice) |
| `aarch64-apple-ios-sim`, `x86_64-apple-ios` | same xcframework (simulator slice) |
