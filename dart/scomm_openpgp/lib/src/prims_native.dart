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
