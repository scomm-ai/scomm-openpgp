import 'dart:ffi';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import 'scomm_openpgp.dart';

/// Digest ids of the native `scomm_prims_*` entry points.
enum NativeHash {
  md5(1),
  sha1(2),
  sha256(3),
  sha384(4),
  sha512(5);

  const NativeHash(this.id);
  final int id;
}

Uint8List nativeDigest(NativeHash alg, List<int> data) =>
    _out('scomm_prims_digest', (arena, out, outLen) {
      final d = _bytes(arena, data);
      return _lib.lookupFunction<
          Int32 Function(
              Int32, Pointer<Uint8>, Size, Pointer<Pointer<Uint8>>, Pointer<Size>),
          int Function(int, Pointer<Uint8>, int, Pointer<Pointer<Uint8>>,
              Pointer<Size>)>('scomm_prims_digest')(alg.id, d.$1, d.$2, out, outLen);
    });

Uint8List nativeHmac(NativeHash alg, List<int> key, List<int> data) =>
    _out('scomm_prims_hmac', (arena, out, outLen) {
      final k = _bytes(arena, key);
      final d = _bytes(arena, data);
      return _lib.lookupFunction<
          Int32 Function(Int32, Pointer<Uint8>, Size, Pointer<Uint8>, Size,
              Pointer<Pointer<Uint8>>, Pointer<Size>),
          int Function(int, Pointer<Uint8>, int, Pointer<Uint8>, int,
              Pointer<Pointer<Uint8>>,
              Pointer<Size>)>('scomm_prims_hmac')(
        alg.id,
        k.$1,
        k.$2,
        d.$1,
        d.$2,
        out,
        outLen,
      );
    });

Uint8List nativePbkdf2(
  NativeHash alg, {
  required List<int> password,
  required List<int> salt,
  required int iterations,
  required int length,
}) =>
    _out('scomm_prims_pbkdf2', (arena, out, outLen) {
      final p = _bytes(arena, password);
      final s = _bytes(arena, salt);
      return _lib.lookupFunction<
          Int32 Function(Int32, Pointer<Uint8>, Size, Pointer<Uint8>, Size, Size,
              Size, Pointer<Pointer<Uint8>>, Pointer<Size>),
          int Function(int, Pointer<Uint8>, int, Pointer<Uint8>, int, int, int,
              Pointer<Pointer<Uint8>>,
              Pointer<Size>)>('scomm_prims_pbkdf2')(
        alg.id,
        p.$1,
        p.$2,
        s.$1,
        s.$2,
        iterations,
        length,
        out,
        outLen,
      );
    });

/// RSASSA-PKCS1-v1_5 with a PKCS#8 (or PKCS#1) DER private key.
Uint8List nativeRsaPkcs1Sign(
  NativeHash alg,
  List<int> privateKeyDer,
  List<int> message,
) =>
    _out('scomm_prims_rsa_pkcs1_sign', (arena, out, outLen) {
      final k = _bytes(arena, privateKeyDer);
      final m = _bytes(arena, message);
      return _lib.lookupFunction<
          Int32 Function(Int32, Pointer<Uint8>, Size, Pointer<Uint8>, Size,
              Pointer<Pointer<Uint8>>, Pointer<Size>),
          int Function(int, Pointer<Uint8>, int, Pointer<Uint8>, int,
              Pointer<Pointer<Uint8>>,
              Pointer<Size>)>('scomm_prims_rsa_pkcs1_sign')(
        alg.id,
        k.$1,
        k.$2,
        m.$1,
        m.$2,
        out,
        outLen,
      );
    });

/// `false` for a bad signature; throws [StateError] for an unusable key.
bool nativeRsaPkcs1Verify(
  NativeHash alg,
  List<int> spkiDer,
  List<int> message,
  List<int> signature,
) =>
    _verdict('scomm_prims_rsa_pkcs1_verify', (arena) {
      final k = _bytes(arena, spkiDer);
      final m = _bytes(arena, message);
      final s = _bytes(arena, signature);
      return _lib.lookupFunction<
          Int32 Function(Int32, Pointer<Uint8>, Size, Pointer<Uint8>, Size,
              Pointer<Uint8>, Size),
          int Function(int, Pointer<Uint8>, int, Pointer<Uint8>, int,
              Pointer<Uint8>, int)>('scomm_prims_rsa_pkcs1_verify')(
        alg.id,
        k.$1,
        k.$2,
        m.$1,
        m.$2,
        s.$1,
        s.$2,
      );
    });

/// ECDSA verify over a SubjectPublicKeyInfo DER key. With [rawSignature] the
/// signature is the JWS `r || s` form; otherwise it is ASN.1 DER.
bool nativeEcdsaVerify(
  NativeHash alg,
  List<int> spkiDer,
  List<int> message,
  List<int> signature, {
  bool rawSignature = false,
}) =>
    _verdict('scomm_prims_ecdsa_verify', (arena) {
      final k = _bytes(arena, spkiDer);
      final m = _bytes(arena, message);
      final s = _bytes(arena, signature);
      return _lib.lookupFunction<
          Int32 Function(Int32, Pointer<Uint8>, Size, Pointer<Uint8>, Size,
              Pointer<Uint8>, Size, Int32),
          int Function(int, Pointer<Uint8>, int, Pointer<Uint8>, int,
              Pointer<Uint8>, int, int)>('scomm_prims_ecdsa_verify')(
        alg.id,
        k.$1,
        k.$2,
        m.$1,
        m.$2,
        s.$1,
        s.$2,
        rawSignature ? 1 : 0,
      );
    });

/// AES-CBC with PKCS#7 padding; the key length (16, 24, 32) picks the cipher.
Uint8List nativeAesCbcEncrypt(
  List<int> key,
  List<int> iv,
  List<int> plaintext,
) =>
    _aesCbc('scomm_prims_aes_cbc_encrypt', key, iv, plaintext);

Uint8List nativeAesCbcDecrypt(
  List<int> key,
  List<int> iv,
  List<int> ciphertext,
) =>
    _aesCbc('scomm_prims_aes_cbc_decrypt', key, iv, ciphertext);

Uint8List _aesCbc(String symbol, List<int> key, List<int> iv, List<int> data) =>
    _out(symbol, (arena, out, outLen) {
      final k = _bytes(arena, key);
      final v = _bytes(arena, iv);
      final d = _bytes(arena, data);
      return _lib.lookupFunction<
          Int32 Function(Pointer<Uint8>, Size, Pointer<Uint8>, Size,
              Pointer<Uint8>, Size, Pointer<Pointer<Uint8>>, Pointer<Size>),
          int Function(Pointer<Uint8>, int, Pointer<Uint8>, int,
              Pointer<Uint8>, int, Pointer<Pointer<Uint8>>,
              Pointer<Size>)>(symbol)(k.$1, k.$2, v.$1, v.$2, d.$1, d.$2, out, outLen);
    });

// The library is a plugin opened with DynamicLibrary.open, so symbols are
// looked up on that handle rather than through @Native.
DynamicLibrary get _lib => ScommOpenPgp.instance.library;

Uint8List _out(
  String symbol,
  int Function(Arena, Pointer<Pointer<Uint8>>, Pointer<Size>) body,
) =>
    using((arena) {
      final out = arena<Pointer<Uint8>>();
      final outLen = arena<Size>();
      if (body(arena, out, outLen) != 0) throw StateError(symbol);
      final bytes = Uint8List.fromList(out.value.asTypedList(outLen.value));
      _lib.lookupFunction<Void Function(Pointer<Uint8>, Size),
          void Function(Pointer<Uint8>, int)>('scomm_openpgp_buffer_free')(
        out.value,
        outLen.value,
      );
      return bytes;
    });

bool _verdict(String symbol, int Function(Arena) body) => using((arena) {
      final rc = body(arena);
      if (rc < 0) throw StateError(symbol);
      return rc == 1;
    });

(Pointer<Uint8>, int) _bytes(Allocator arena, List<int> bytes) {
  if (bytes.isEmpty) return (nullptr, 0);
  final ptr = arena<Uint8>(bytes.length);
  ptr.asTypedList(bytes.length).setAll(0, bytes);
  return (ptr, bytes.length);
}
