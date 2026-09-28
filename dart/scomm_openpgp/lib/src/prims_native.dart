import 'dart:ffi';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import 'scomm_openpgp.dart';

@Native<
    Int32 Function(
      Pointer<Uint8>,
      Size,
      Pointer<Pointer<Uint8>>,
      Pointer<Size>,
    )>(symbol: 'scomm_prims_sha256', isLeaf: true)
external int _sha256(
  Pointer<Uint8> data,
  int dataLen,
  Pointer<Pointer<Uint8>> out,
  Pointer<Size> outLen,
);

@Native<
    Int32 Function(
      Pointer<Uint8>,
      Size,
      Pointer<Uint8>,
      Size,
      Pointer<Pointer<Uint8>>,
      Pointer<Size>,
    )>(symbol: 'scomm_prims_hmac_sha256', isLeaf: true)
external int _hmacSha256(
  Pointer<Uint8> key,
  int keyLen,
  Pointer<Uint8> data,
  int dataLen,
  Pointer<Pointer<Uint8>> out,
  Pointer<Size> outLen,
);

@Native<
    Int32 Function(
      Pointer<Uint8>,
      Size,
      Pointer<Pointer<Uint8>>,
      Pointer<Size>,
    )>(symbol: 'scomm_prims_sha512', isLeaf: true)
external int _sha512(
  Pointer<Uint8> data,
  int dataLen,
  Pointer<Pointer<Uint8>> out,
  Pointer<Size> outLen,
);

Uint8List nativeSha512(List<int> data) {
  ScommOpenPgp.instance;
  return using((arena) {
    final input = _bytes(arena, data);
    final out = arena<Pointer<Uint8>>();
    final outLen = arena<Size>();
    final rc = _sha512(input.$1, input.$2, out, outLen);
    if (rc != 0) {
      throw StateError('scomm_prims_sha512');
    }
    return _take(out.value, outLen.value);
  });
}

Uint8List nativeSha256(List<int> data) {
  ScommOpenPgp.instance;
  return using((arena) {
    final input = _bytes(arena, data);
    final out = arena<Pointer<Uint8>>();
    final outLen = arena<Size>();
    final rc = _sha256(input.$1, input.$2, out, outLen);
    if (rc != 0) {
      throw StateError('scomm_prims_sha256');
    }
    return _take(out.value, outLen.value);
  });
}

Uint8List nativeHmacSha256(List<int> key, List<int> data) {
  ScommOpenPgp.instance;
  return using((arena) {
    final k = _bytes(arena, key);
    final d = _bytes(arena, data);
    final out = arena<Pointer<Uint8>>();
    final outLen = arena<Size>();
    final rc = _hmacSha256(k.$1, k.$2, d.$1, d.$2, out, outLen);
    if (rc != 0) {
      throw StateError('scomm_prims_hmac_sha256');
    }
    return _take(out.value, outLen.value);
  });
}

@Native<
    Int32 Function(
      Pointer<Uint8>,
      Size,
      Pointer<Uint8>,
      Size,
      Pointer<Uint8>,
      Size,
      Pointer<Uint8>,
      Size,
      Pointer<Pointer<Uint8>>,
      Pointer<Size>,
      Pointer<Pointer<Uint8>>,
      Pointer<Size>,
    )>(symbol: 'scomm_prims_aes256gcm_encrypt', isLeaf: true)
external int _aesEncrypt(
  Pointer<Uint8> key,
  int keyLen,
  Pointer<Uint8> nonce,
  int nonceLen,
  Pointer<Uint8> aad,
  int aadLen,
  Pointer<Uint8> plaintext,
  int plaintextLen,
  Pointer<Pointer<Uint8>> ctOut,
  Pointer<Size> ctLen,
  Pointer<Pointer<Uint8>> tagOut,
  Pointer<Size> tagLen,
);

@Native<
    Int32 Function(
      Pointer<Uint8>,
      Size,
      Pointer<Uint8>,
      Size,
      Pointer<Uint8>,
      Size,
      Pointer<Uint8>,
      Size,
      Pointer<Uint8>,
      Size,
      Pointer<Pointer<Uint8>>,
      Pointer<Size>,
    )>(symbol: 'scomm_prims_aes256gcm_decrypt', isLeaf: true)
external int _aesDecrypt(
  Pointer<Uint8> key,
  int keyLen,
  Pointer<Uint8> nonce,
  int nonceLen,
  Pointer<Uint8> aad,
  int aadLen,
  Pointer<Uint8> ciphertext,
  int ciphertextLen,
  Pointer<Uint8> tag,
  int tagLen,
  Pointer<Pointer<Uint8>> out,
  Pointer<Size> outLen,
);

@Native<
    Int32 Function(
      Pointer<Uint8>,
      Size,
      Pointer<Uint8>,
      Size,
      Uint32,
      Uint32,
      Uint32,
      Size,
      Pointer<Pointer<Uint8>>,
      Pointer<Size>,
    )>(symbol: 'scomm_prims_argon2id', isLeaf: true)
external int _argon2id(
  Pointer<Uint8> password,
  int passwordLen,
  Pointer<Uint8> salt,
  int saltLen,
  int iterations,
  int lanes,
  int memKib,
  int outLen,
  Pointer<Pointer<Uint8>> out,
  Pointer<Size> outOutLen,
);

@Native<Int32 Function(Size, Pointer<Pointer<Uint8>>, Pointer<Size>)>(
  symbol: 'scomm_prims_random',
  isLeaf: true,
)
external int _random(int n, Pointer<Pointer<Uint8>> out, Pointer<Size> outLen);

@Native<
    Int32 Function(
      Pointer<Uint8>,
      Size,
      Pointer<Uint8>,
      Size,
      Pointer<Pointer<Uint8>>,
      Pointer<Size>,
    )>(symbol: 'scomm_prims_ed25519_sign', isLeaf: true)
external int _ed25519Sign(
  Pointer<Uint8> seed,
  int seedLen,
  Pointer<Uint8> message,
  int messageLen,
  Pointer<Pointer<Uint8>> out,
  Pointer<Size> outLen,
);

@Native<
    Int32 Function(
      Pointer<Uint8>,
      Size,
      Pointer<Pointer<Uint8>>,
      Pointer<Size>,
    )>(symbol: 'scomm_prims_ed25519_public', isLeaf: true)
external int _ed25519Public(
  Pointer<Uint8> seed,
  int seedLen,
  Pointer<Pointer<Uint8>> out,
  Pointer<Size> outLen,
);

@Native<
    Int32 Function(
      Pointer<Uint8>,
      Size,
      Pointer<Uint8>,
      Size,
      Pointer<Uint8>,
      Size,
    )>(symbol: 'scomm_prims_ed25519_verify', isLeaf: true)
external int _ed25519Verify(
  Pointer<Uint8> publicKey,
  int publicKeyLen,
  Pointer<Uint8> message,
  int messageLen,
  Pointer<Uint8> signature,
  int signatureLen,
);

@Native<
    Int32 Function(
      Pointer<Uint8>,
      Size,
      Pointer<Pointer<Uint8>>,
      Pointer<Size>,
    )>(symbol: 'scomm_prims_x25519_public', isLeaf: true)
external int _x25519Public(
  Pointer<Uint8> seed,
  int seedLen,
  Pointer<Pointer<Uint8>> out,
  Pointer<Size> outLen,
);

@Native<
    Int32 Function(
      Pointer<Uint8>,
      Size,
      Pointer<Uint8>,
      Size,
      Pointer<Pointer<Uint8>>,
      Pointer<Size>,
    )>(symbol: 'scomm_prims_x25519_dh', isLeaf: true)
external int _x25519Dh(
  Pointer<Uint8> seed,
  int seedLen,
  Pointer<Uint8> peer,
  int peerLen,
  Pointer<Pointer<Uint8>> out,
  Pointer<Size> outLen,
);

Uint8List nativeRandom(int n) {
  ScommOpenPgp.instance;
  return using((arena) {
    final out = arena<Pointer<Uint8>>();
    final outLen = arena<Size>();
    final rc = _random(n, out, outLen);
    if (rc != 0) throw StateError('scomm_prims_random');
    return _take(out.value, outLen.value);
  });
}

({Uint8List ciphertext, Uint8List tag}) nativeAes256GcmEncrypt({
  required List<int> key,
  required List<int> nonce,
  required List<int> plaintext,
  List<int> aad = const [],
}) {
  ScommOpenPgp.instance;
  return using((arena) {
    final k = _bytes(arena, key);
    final n = _bytes(arena, nonce);
    final a = _bytes(arena, aad);
    final p = _bytes(arena, plaintext);
    final ct = arena<Pointer<Uint8>>();
    final ctLen = arena<Size>();
    final tag = arena<Pointer<Uint8>>();
    final tagLen = arena<Size>();
    final rc = _aesEncrypt(
      k.$1, k.$2, n.$1, n.$2, a.$1, a.$2, p.$1, p.$2, ct, ctLen, tag, tagLen,
    );
    if (rc != 0) throw StateError('scomm_prims_aes256gcm_encrypt');
    return (
      ciphertext: _take(ct.value, ctLen.value),
      tag: _take(tag.value, tagLen.value),
    );
  });
}

Uint8List nativeAes256GcmDecrypt({
  required List<int> key,
  required List<int> nonce,
  required List<int> ciphertext,
  required List<int> tag,
  List<int> aad = const [],
}) {
  ScommOpenPgp.instance;
  return using((arena) {
    final k = _bytes(arena, key);
    final n = _bytes(arena, nonce);
    final a = _bytes(arena, aad);
    final c = _bytes(arena, ciphertext);
    final t = _bytes(arena, tag);
    final out = arena<Pointer<Uint8>>();
    final outLen = arena<Size>();
    final rc = _aesDecrypt(
      k.$1, k.$2, n.$1, n.$2, a.$1, a.$2, c.$1, c.$2, t.$1, t.$2, out, outLen,
    );
    if (rc != 0) throw StateError('scomm_prims_aes256gcm_decrypt');
    return _take(out.value, outLen.value);
  });
}

Uint8List nativeArgon2id({
  required List<int> password,
  required List<int> salt,
  required int iterations,
  required int lanes,
  required int memKib,
  required int outLen,
}) {
  ScommOpenPgp.instance;
  return using((arena) {
    final p = _bytes(arena, password);
    final s = _bytes(arena, salt);
    final out = arena<Pointer<Uint8>>();
    final got = arena<Size>();
    final rc = _argon2id(
      p.$1, p.$2, s.$1, s.$2, iterations, lanes, memKib, outLen, out, got,
    );
    if (rc != 0) throw StateError('scomm_prims_argon2id');
    return _take(out.value, got.value);
  });
}

Uint8List nativeEd25519Public(List<int> seed) {
  ScommOpenPgp.instance;
  return using((arena) {
    final s = _bytes(arena, seed);
    final out = arena<Pointer<Uint8>>();
    final outLen = arena<Size>();
    final rc = _ed25519Public(s.$1, s.$2, out, outLen);
    if (rc != 0) throw StateError('scomm_prims_ed25519_public');
    return _take(out.value, outLen.value);
  });
}

Uint8List nativeEd25519Sign(List<int> seed, List<int> message) {
  ScommOpenPgp.instance;
  return using((arena) {
    final s = _bytes(arena, seed);
    final m = _bytes(arena, message);
    final out = arena<Pointer<Uint8>>();
    final outLen = arena<Size>();
    final rc = _ed25519Sign(s.$1, s.$2, m.$1, m.$2, out, outLen);
    if (rc != 0) throw StateError('scomm_prims_ed25519_sign');
    return _take(out.value, outLen.value);
  });
}

bool nativeEd25519Verify(
  List<int> publicKey,
  List<int> message,
  List<int> signature,
) {
  ScommOpenPgp.instance;
  return using((arena) {
    final p = _bytes(arena, publicKey);
    final m = _bytes(arena, message);
    final s = _bytes(arena, signature);
    final rc = _ed25519Verify(p.$1, p.$2, m.$1, m.$2, s.$1, s.$2);
    if (rc < 0) throw StateError('scomm_prims_ed25519_verify');
    return rc == 1;
  });
}

Uint8List nativeX25519Public(List<int> seed) {
  ScommOpenPgp.instance;
  return using((arena) {
    final s = _bytes(arena, seed);
    final out = arena<Pointer<Uint8>>();
    final outLen = arena<Size>();
    final rc = _x25519Public(s.$1, s.$2, out, outLen);
    if (rc != 0) throw StateError('scomm_prims_x25519_public');
    return _take(out.value, outLen.value);
  });
}

Uint8List nativeX25519Dh(List<int> seed, List<int> peer) {
  ScommOpenPgp.instance;
  return using((arena) {
    final s = _bytes(arena, seed);
    final p = _bytes(arena, peer);
    final out = arena<Pointer<Uint8>>();
    final outLen = arena<Size>();
    final rc = _x25519Dh(s.$1, s.$2, p.$1, p.$2, out, outLen);
    if (rc != 0) throw StateError('scomm_prims_x25519_dh');
    return _take(out.value, outLen.value);
  });
}

(Pointer<Uint8>, int) _bytes(Allocator arena, List<int> bytes) {
  if (bytes.isEmpty) return (nullptr, 0);
  final ptr = arena<Uint8>(bytes.length);
  ptr.asTypedList(bytes.length).setAll(0, bytes);
  return (ptr, bytes.length);
}

Uint8List _take(Pointer<Uint8> ptr, int len) {
  final bytes = Uint8List.fromList(ptr.asTypedList(len));
  ScommOpenPgp.instance.library.lookupFunction<
      Void Function(Pointer<Uint8>, Size),
      void Function(Pointer<Uint8>, int)>('scomm_openpgp_buffer_free')(ptr, len);
  return bytes;
}
