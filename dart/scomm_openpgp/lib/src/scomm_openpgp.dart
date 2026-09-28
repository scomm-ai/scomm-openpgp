import 'dart:convert';
import 'dart:ffi' as ffi;
import 'dart:io';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import 'types.dart';

typedef _AbiVersionN = ffi.Uint32 Function();
typedef _AbiVersionD = int Function();
typedef _BufferFreeN = ffi.Void Function(ffi.Pointer<ffi.Uint8>, ffi.Size);
typedef _BufferFreeD = void Function(ffi.Pointer<ffi.Uint8>, int);
typedef _LastErrorN = ffi.Int32 Function(
  ffi.Pointer<ffi.Pointer<ffi.Uint8>>,
  ffi.Pointer<ffi.Size>,
);
typedef _LastErrorD = int Function(
  ffi.Pointer<ffi.Pointer<ffi.Uint8>>,
  ffi.Pointer<ffi.Size>,
);
typedef _InspectN = ffi.Int32 Function(
  ffi.Pointer<ffi.Uint8>,
  ffi.Size,
  ffi.Pointer<ffi.Pointer<ffi.Uint8>>,
  ffi.Pointer<ffi.Size>,
);
typedef _InspectD = int Function(
  ffi.Pointer<ffi.Uint8>,
  int,
  ffi.Pointer<ffi.Pointer<ffi.Uint8>>,
  ffi.Pointer<ffi.Size>,
);
typedef _GenerateN = ffi.Int32 Function(
  ffi.Pointer<ffi.Uint8>,
  ffi.Size,
  ffi.Pointer<ffi.Uint8>,
  ffi.Size,
  ffi.Int32,
  ffi.Pointer<ffi.Pointer<ffi.Uint8>>,
  ffi.Pointer<ffi.Size>,
  ffi.Pointer<ffi.Pointer<ffi.Uint8>>,
  ffi.Pointer<ffi.Size>,
  ffi.Pointer<ffi.Pointer<ffi.Uint8>>,
  ffi.Pointer<ffi.Size>,
);
typedef _GenerateD = int Function(
  ffi.Pointer<ffi.Uint8>,
  int,
  ffi.Pointer<ffi.Uint8>,
  int,
  int,
  ffi.Pointer<ffi.Pointer<ffi.Uint8>>,
  ffi.Pointer<ffi.Size>,
  ffi.Pointer<ffi.Pointer<ffi.Uint8>>,
  ffi.Pointer<ffi.Size>,
  ffi.Pointer<ffi.Pointer<ffi.Uint8>>,
  ffi.Pointer<ffi.Size>,
);
typedef _Rfc9980ReadyN = ffi.Int32 Function();
typedef _Rfc9980ReadyD = int Function();
typedef _ExportN = ffi.Int32 Function(
  ffi.Pointer<ffi.Uint8>,
  ffi.Size,
  ffi.Pointer<ffi.Pointer<ffi.Uint8>>,
  ffi.Pointer<ffi.Size>,
);
typedef _ExportD = int Function(
  ffi.Pointer<ffi.Uint8>,
  int,
  ffi.Pointer<ffi.Pointer<ffi.Uint8>>,
  ffi.Pointer<ffi.Size>,
);
typedef _ArmorN = ffi.Int32 Function(
  ffi.Int32,
  ffi.Pointer<ffi.Uint8>,
  ffi.Size,
  ffi.Pointer<ffi.Pointer<ffi.Uint8>>,
  ffi.Pointer<ffi.Size>,
);
typedef _ArmorD = int Function(
  int,
  ffi.Pointer<ffi.Uint8>,
  int,
  ffi.Pointer<ffi.Pointer<ffi.Uint8>>,
  ffi.Pointer<ffi.Size>,
);
typedef _EncryptN = ffi.Int32 Function(
  ffi.Pointer<ffi.Uint8>,
  ffi.Size,
  ffi.Pointer<ffi.Uint8>,
  ffi.Size,
  ffi.Int32,
  ffi.Pointer<ffi.Pointer<ffi.Uint8>>,
  ffi.Pointer<ffi.Size>,
);
typedef _EncryptD = int Function(
  ffi.Pointer<ffi.Uint8>,
  int,
  ffi.Pointer<ffi.Uint8>,
  int,
  int,
  ffi.Pointer<ffi.Pointer<ffi.Uint8>>,
  ffi.Pointer<ffi.Size>,
);
typedef _DecryptN = ffi.Int32 Function(
  ffi.Pointer<ffi.Uint8>,
  ffi.Size,
  ffi.Pointer<ffi.Uint8>,
  ffi.Size,
  ffi.Pointer<ffi.Uint8>,
  ffi.Size,
  ffi.Pointer<ffi.Pointer<ffi.Uint8>>,
  ffi.Pointer<ffi.Size>,
);
typedef _DecryptD = int Function(
  ffi.Pointer<ffi.Uint8>,
  int,
  ffi.Pointer<ffi.Uint8>,
  int,
  ffi.Pointer<ffi.Uint8>,
  int,
  ffi.Pointer<ffi.Pointer<ffi.Uint8>>,
  ffi.Pointer<ffi.Size>,
);
typedef _SignN = ffi.Int32 Function(
  ffi.Pointer<ffi.Uint8>,
  ffi.Size,
  ffi.Pointer<ffi.Uint8>,
  ffi.Size,
  ffi.Pointer<ffi.Uint8>,
  ffi.Size,
  ffi.Int32,
  ffi.Int32,
  ffi.Pointer<ffi.Pointer<ffi.Uint8>>,
  ffi.Pointer<ffi.Size>,
);
typedef _SignD = int Function(
  ffi.Pointer<ffi.Uint8>,
  int,
  ffi.Pointer<ffi.Uint8>,
  int,
  ffi.Pointer<ffi.Uint8>,
  int,
  int,
  int,
  ffi.Pointer<ffi.Pointer<ffi.Uint8>>,
  ffi.Pointer<ffi.Size>,
);
typedef _VerifyN = ffi.Int32 Function(
  ffi.Pointer<ffi.Uint8>,
  ffi.Size,
  ffi.Pointer<ffi.Uint8>,
  ffi.Size,
  ffi.Pointer<ffi.Uint8>,
  ffi.Size,
  ffi.Pointer<ffi.Int32>,
);
typedef _VerifyD = int Function(
  ffi.Pointer<ffi.Uint8>,
  int,
  ffi.Pointer<ffi.Uint8>,
  int,
  ffi.Pointer<ffi.Uint8>,
  int,
  ffi.Pointer<ffi.Int32>,
);
typedef _TestPassN = ffi.Int32 Function(
  ffi.Pointer<ffi.Uint8>,
  ffi.Size,
  ffi.Pointer<ffi.Uint8>,
  ffi.Size,
);
typedef _TestPassD = int Function(
  ffi.Pointer<ffi.Uint8>,
  int,
  ffi.Pointer<ffi.Uint8>,
  int,
);
typedef _PopSignN = ffi.Int32 Function(
  ffi.Pointer<ffi.Uint8>,
  ffi.Size,
  ffi.Pointer<ffi.Uint8>,
  ffi.Size,
  ffi.Pointer<ffi.Uint8>,
  ffi.Size,
  ffi.Pointer<ffi.Pointer<ffi.Uint8>>,
  ffi.Pointer<ffi.Size>,
  ffi.Pointer<ffi.Pointer<ffi.Uint8>>,
  ffi.Pointer<ffi.Size>,
);
typedef _PopSignD = int Function(
  ffi.Pointer<ffi.Uint8>,
  int,
  ffi.Pointer<ffi.Uint8>,
  int,
  ffi.Pointer<ffi.Uint8>,
  int,
  ffi.Pointer<ffi.Pointer<ffi.Uint8>>,
  ffi.Pointer<ffi.Size>,
  ffi.Pointer<ffi.Pointer<ffi.Uint8>>,
  ffi.Pointer<ffi.Size>,
);
typedef _PopHybridN = ffi.Int32 Function(
  ffi.Pointer<ffi.Uint8>,
  ffi.Size,
  ffi.Pointer<ffi.Uint8>,
  ffi.Size,
  ffi.Pointer<ffi.Uint8>,
  ffi.Size,
  ffi.Pointer<ffi.Uint8>,
  ffi.Size,
  ffi.Pointer<ffi.Pointer<ffi.Uint8>>,
  ffi.Pointer<ffi.Size>,
);
typedef _Sha256N = ffi.Int32 Function(
  ffi.Pointer<ffi.Uint8>,
  ffi.Size,
  ffi.Pointer<ffi.Pointer<ffi.Uint8>>,
  ffi.Pointer<ffi.Size>,
);
typedef _Sha256D = int Function(
  ffi.Pointer<ffi.Uint8>,
  int,
  ffi.Pointer<ffi.Pointer<ffi.Uint8>>,
  ffi.Pointer<ffi.Size>,
);
typedef _PopHybridD = int Function(
  ffi.Pointer<ffi.Uint8>,
  int,
  ffi.Pointer<ffi.Uint8>,
  int,
  ffi.Pointer<ffi.Uint8>,
  int,
  ffi.Pointer<ffi.Uint8>,
  int,
  ffi.Pointer<ffi.Pointer<ffi.Uint8>>,
  ffi.Pointer<ffi.Size>,
);

/// Bytes-in / bytes-out OpenPGP. Sequoia does not appear in this API.
class ScommOpenPgp {
  ScommOpenPgp._(this._lib)
      : _abiVersion = _lib.lookupFunction<_AbiVersionN, _AbiVersionD>(
          'scomm_openpgp_abi_version',
        ),
        _bufferFree = _lib.lookupFunction<_BufferFreeN, _BufferFreeD>(
          'scomm_openpgp_buffer_free',
        ),
        _lastError = _lib.lookupFunction<_LastErrorN, _LastErrorD>(
          'scomm_openpgp_last_error',
        ),
        _inspect = _lib.lookupFunction<_InspectN, _InspectD>(
          'scomm_openpgp_inspect',
        ),
        _generate = _lib.lookupFunction<_GenerateN, _GenerateD>(
          'scomm_openpgp_generate',
        ),
        _rfc9980Ready = _lib.lookupFunction<_Rfc9980ReadyN, _Rfc9980ReadyD>(
          'scomm_openpgp_rfc9980_ready',
        ),
        _exportPublic = _lib.lookupFunction<_ExportN, _ExportD>(
          'scomm_openpgp_export_public',
        ),
        _armor = _lib.lookupFunction<_ArmorN, _ArmorD>(
          'scomm_openpgp_armor',
        ),
        _encrypt = _lib.lookupFunction<_EncryptN, _EncryptD>(
          'scomm_openpgp_encrypt',
        ),
        _decrypt = _lib.lookupFunction<_DecryptN, _DecryptD>(
          'scomm_openpgp_decrypt',
        ),
        _sign = _lib.lookupFunction<_SignN, _SignD>('scomm_openpgp_sign'),
        _verify = _lib.lookupFunction<_VerifyN, _VerifyD>(
          'scomm_openpgp_verify',
        ),
        _testPass = _lib.lookupFunction<_TestPassN, _TestPassD>(
          'scomm_openpgp_test_passphrase',
        ),
        _popSign = _lib.lookupFunction<_PopSignN, _PopSignD>(
          'scomm_openpgp_pop_sign_composite',
        ),
        _popHybrid = _lib.lookupFunction<_PopHybridN, _PopHybridD>(
          'scomm_openpgp_pop_hybrid_shared',
        ),
        _sha256 = _lib.lookupFunction<_Sha256N, _Sha256D>('scomm_prims_sha256');

  static ScommOpenPgp? _instance;

  static ScommOpenPgp get instance => _instance ??= ScommOpenPgp._(_open());

  /// The loaded `libscomm_openpgp` handle. Other packages bind leaf symbols
  /// with `@Native` against this library; they do not open a second one.
  ffi.DynamicLibrary get library => _lib;

  final ffi.DynamicLibrary _lib;
  final int Function(
    ffi.Pointer<ffi.Uint8>,
    int,
    ffi.Pointer<ffi.Pointer<ffi.Uint8>>,
    ffi.Pointer<ffi.Size>,
  ) _sha256;
  final int Function() _abiVersion;
  final void Function(ffi.Pointer<ffi.Uint8>, int) _bufferFree;
  final int Function(
    ffi.Pointer<ffi.Pointer<ffi.Uint8>>,
    ffi.Pointer<ffi.Size>,
  ) _lastError;
  final int Function(
    ffi.Pointer<ffi.Uint8>,
    int,
    ffi.Pointer<ffi.Pointer<ffi.Uint8>>,
    ffi.Pointer<ffi.Size>,
  ) _inspect;
  final int Function(
    ffi.Pointer<ffi.Uint8>,
    int,
    ffi.Pointer<ffi.Uint8>,
    int,
    int,
    ffi.Pointer<ffi.Pointer<ffi.Uint8>>,
    ffi.Pointer<ffi.Size>,
    ffi.Pointer<ffi.Pointer<ffi.Uint8>>,
    ffi.Pointer<ffi.Size>,
    ffi.Pointer<ffi.Pointer<ffi.Uint8>>,
    ffi.Pointer<ffi.Size>,
  ) _generate;
  final int Function() _rfc9980Ready;
  final int Function(
    ffi.Pointer<ffi.Uint8>,
    int,
    ffi.Pointer<ffi.Pointer<ffi.Uint8>>,
    ffi.Pointer<ffi.Size>,
  ) _exportPublic;
  final int Function(
    int,
    ffi.Pointer<ffi.Uint8>,
    int,
    ffi.Pointer<ffi.Pointer<ffi.Uint8>>,
    ffi.Pointer<ffi.Size>,
  ) _armor;
  final int Function(
    ffi.Pointer<ffi.Uint8>,
    int,
    ffi.Pointer<ffi.Uint8>,
    int,
    int,
    ffi.Pointer<ffi.Pointer<ffi.Uint8>>,
    ffi.Pointer<ffi.Size>,
  ) _encrypt;
  final int Function(
    ffi.Pointer<ffi.Uint8>,
    int,
    ffi.Pointer<ffi.Uint8>,
    int,
    ffi.Pointer<ffi.Uint8>,
    int,
    ffi.Pointer<ffi.Pointer<ffi.Uint8>>,
    ffi.Pointer<ffi.Size>,
  ) _decrypt;
  final int Function(
    ffi.Pointer<ffi.Uint8>,
    int,
    ffi.Pointer<ffi.Uint8>,
    int,
    ffi.Pointer<ffi.Uint8>,
    int,
    int,
    int,
    ffi.Pointer<ffi.Pointer<ffi.Uint8>>,
    ffi.Pointer<ffi.Size>,
  ) _sign;
  final int Function(
    ffi.Pointer<ffi.Uint8>,
    int,
    ffi.Pointer<ffi.Uint8>,
    int,
    ffi.Pointer<ffi.Uint8>,
    int,
    ffi.Pointer<ffi.Int32>,
  ) _verify;
  final int Function(ffi.Pointer<ffi.Uint8>, int, ffi.Pointer<ffi.Uint8>, int)
      _testPass;
  final _PopSignD _popSign;
  final _PopHybridD _popHybrid;

  int get abiVersion => _abiVersion();

  bool get rfc9980Ready => _rfc9980Ready() != 0;

  OpenPgpKeyInspect inspectKey(List<int> key) {
    return OpenPgpKeyInspect.fromJson(
      jsonDecode(utf8.decode(_call1(key, _inspect))) as Map<String, dynamic>,
    );
  }

  GeneratedOpenPgpKey generateKey({
    required String userid,
    String passphrase = '',
    OpenPgpKeyProfile profile = OpenPgpKeyProfile.classicalCv25519,
  }) {
    return using((arena) {
      final user = _copy(arena, utf8.encode(userid));
      final pass = _copy(arena, utf8.encode(passphrase));
      final pubPtr = arena<ffi.Pointer<ffi.Uint8>>();
      final pubLen = arena<ffi.Size>();
      final secPtr = arena<ffi.Pointer<ffi.Uint8>>();
      final secLen = arena<ffi.Size>();
      final jsonPtr = arena<ffi.Pointer<ffi.Uint8>>();
      final jsonLen = arena<ffi.Size>();
      final code = _generate(
        user.ptr,
        user.len,
        pass.ptr,
        pass.len,
        profile.wire,
        pubPtr,
        pubLen,
        secPtr,
        secLen,
        jsonPtr,
        jsonLen,
      );
      if (code != 0) {
        throw ScommOpenPgpException(code, _readLastError());
      }
      final public = _take(pubPtr.value, pubLen.value);
      final secret = _take(secPtr.value, secLen.value);
      final infoJson = utf8.decode(_take(jsonPtr.value, jsonLen.value));
      return GeneratedOpenPgpKey(
        public: public,
        secret: secret,
        info: OpenPgpKeyInspect.fromJson(
          jsonDecode(infoJson) as Map<String, dynamic>,
        ),
      );
    });
  }

  Uint8List exportPublicKey(List<int> secretOrPublic) {
    return Uint8List.fromList(_call1(secretOrPublic, _exportPublic));
  }

  String armorPublicKey(List<int> binary) {
    return utf8.decode(_callArmor(0, binary));
  }

  String armorSecretKey(List<int> binary) {
    return utf8.decode(_callArmor(1, binary));
  }

  String armorSignature(List<int> binary) {
    return utf8.decode(_callArmor(2, binary));
  }

  String armorMessage(List<int> binary) {
    return utf8.decode(_callArmor(3, binary));
  }

  Uint8List encrypt({
    required List<int> plaintext,
    required List<List<int>> recipientPublicKeys,
    bool armored = false,
  }) {
    return using((arena) {
      final pt = _copy(arena, plaintext);
      final recips = _copy(arena, _encodeRecipients(recipientPublicKeys));
      final outPtr = arena<ffi.Pointer<ffi.Uint8>>();
      final outLen = arena<ffi.Size>();
      final code = _encrypt(
        pt.ptr,
        pt.len,
        recips.ptr,
        recips.len,
        armored ? 1 : 0,
        outPtr,
        outLen,
      );
      if (code != 0) {
        throw ScommOpenPgpException(code, _readLastError());
      }
      return Uint8List.fromList(_take(outPtr.value, outLen.value));
    });
  }

  Uint8List decrypt({
    required List<int> ciphertext,
    required List<int> privateKey,
    String passphrase = '',
  }) {
    return using((arena) {
      final ct = _copy(arena, ciphertext);
      final sk = _copy(arena, privateKey);
      final pass = _copy(arena, utf8.encode(passphrase));
      final outPtr = arena<ffi.Pointer<ffi.Uint8>>();
      final outLen = arena<ffi.Size>();
      final code = _decrypt(
        ct.ptr,
        ct.len,
        sk.ptr,
        sk.len,
        pass.ptr,
        pass.len,
        outPtr,
        outLen,
      );
      if (code != 0) {
        throw ScommOpenPgpException(code, _readLastError());
      }
      return Uint8List.fromList(_take(outPtr.value, outLen.value));
    });
  }

  Uint8List signDetached({
    required List<int> data,
    required List<int> privateKey,
    String passphrase = '',
    bool armored = false,
  }) {
    return using((arena) {
      final d = _copy(arena, data);
      final sk = _copy(arena, privateKey);
      final pass = _copy(arena, utf8.encode(passphrase));
      final outPtr = arena<ffi.Pointer<ffi.Uint8>>();
      final outLen = arena<ffi.Size>();
      final code = _sign(
        d.ptr,
        d.len,
        sk.ptr,
        sk.len,
        pass.ptr,
        pass.len,
        armored ? 1 : 0,
        1,
        outPtr,
        outLen,
      );
      if (code != 0) {
        throw ScommOpenPgpException(code, _readLastError());
      }
      return Uint8List.fromList(_take(outPtr.value, outLen.value));
    });
  }

  bool verifyDetached({
    required List<int> data,
    required List<int> signature,
    required List<int> publicKey,
  }) {
    return using((arena) {
      final d = _copy(arena, data);
      final sig = _copy(arena, signature);
      final pk = _copy(arena, publicKey);
      final valid = arena<ffi.Int32>();
      final code = _verify(
        d.ptr,
        d.len,
        sig.ptr,
        sig.len,
        pk.ptr,
        pk.len,
        valid,
      );
      if (code != 0) {
        throw ScommOpenPgpException(code, _readLastError());
      }
      return valid.value != 0;
    });
  }

  void testPassphrase({
    required List<int> privateKey,
    String passphrase = '',
  }) {
    using((arena) {
      final sk = _copy(arena, privateKey);
      final pass = _copy(arena, utf8.encode(passphrase));
      final code = _testPass(sk.ptr, sk.len, pass.ptr, pass.len);
      if (code != 0) {
        throw ScommOpenPgpException(code, _readLastError());
      }
    });
  }

  CompositePopSignatures popSignComposite({
    required List<int> data,
    required List<int> privateKey,
    String passphrase = '',
  }) {
    return using((arena) {
      final d = _copy(arena, data);
      final sk = _copy(arena, privateKey);
      final pass = _copy(arena, utf8.encode(passphrase));
      final mlPtr = arena<ffi.Pointer<ffi.Uint8>>();
      final mlLen = arena<ffi.Size>();
      final edPtr = arena<ffi.Pointer<ffi.Uint8>>();
      final edLen = arena<ffi.Size>();
      final code = _popSign(
        d.ptr,
        d.len,
        sk.ptr,
        sk.len,
        pass.ptr,
        pass.len,
        mlPtr,
        mlLen,
        edPtr,
        edLen,
      );
      if (code != 0) {
        throw ScommOpenPgpException(code, _readLastError());
      }
      return CompositePopSignatures(
        mldsa: Uint8List.fromList(_take(mlPtr.value, mlLen.value)),
        ed25519: Uint8List.fromList(_take(edPtr.value, edLen.value)),
      );
    });
  }

  /// Returns `mlkem_shared || x25519_shared` (64 octets). Hash with SHA-256 for AES wrap.
  Uint8List popHybridShared({
    required List<int> privateKey,
    required List<int> kemCiphertext,
    required List<int> ephemeralX25519,
    String passphrase = '',
  }) {
    return using((arena) {
      final sk = _copy(arena, privateKey);
      final pass = _copy(arena, utf8.encode(passphrase));
      final kem = _copy(arena, kemCiphertext);
      final eph = _copy(arena, ephemeralX25519);
      final outPtr = arena<ffi.Pointer<ffi.Uint8>>();
      final outLen = arena<ffi.Size>();
      final code = _popHybrid(
        sk.ptr,
        sk.len,
        pass.ptr,
        pass.len,
        kem.ptr,
        kem.len,
        eph.ptr,
        eph.len,
        outPtr,
        outLen,
      );
      if (code != 0) {
        throw ScommOpenPgpException(code, _readLastError());
      }
      return Uint8List.fromList(_take(outPtr.value, outLen.value));
    });
  }

  List<int> _call1(
    List<int> input,
    int Function(
      ffi.Pointer<ffi.Uint8>,
      int,
      ffi.Pointer<ffi.Pointer<ffi.Uint8>>,
      ffi.Pointer<ffi.Size>,
    ) fn,
  ) {
    return using((arena) {
      final buf = _copy(arena, input);
      final outPtr = arena<ffi.Pointer<ffi.Uint8>>();
      final outLen = arena<ffi.Size>();
      final code = fn(buf.ptr, buf.len, outPtr, outLen);
      if (code != 0) {
        throw ScommOpenPgpException(code, _readLastError());
      }
      return _take(outPtr.value, outLen.value);
    });
  }

  List<int> _callArmor(int kind, List<int> binary) {
    return using((arena) {
      final buf = _copy(arena, binary);
      final outPtr = arena<ffi.Pointer<ffi.Uint8>>();
      final outLen = arena<ffi.Size>();
      final code = _armor(kind, buf.ptr, buf.len, outPtr, outLen);
      if (code != 0) {
        throw ScommOpenPgpException(code, _readLastError());
      }
      return _take(outPtr.value, outLen.value);
    });
  }

  String _readLastError() {
    return using((arena) {
      final outPtr = arena<ffi.Pointer<ffi.Uint8>>();
      final outLen = arena<ffi.Size>();
      _lastError(outPtr, outLen);
      return utf8.decode(_take(outPtr.value, outLen.value));
    });
  }

  Uint8List sha256(List<int> data) {
    return using((arena) {
      final input = _copy(arena, data);
      final outPtr = arena<ffi.Pointer<ffi.Uint8>>();
      final outLen = arena<ffi.Size>();
      final rc = _sha256(input.ptr, input.len, outPtr, outLen);
      if (rc != 0) {
        throw ScommOpenPgpException(rc, _readLastError());
      }
      return Uint8List.fromList(_take(outPtr.value, outLen.value));
    });
  }

  List<int> _take(ffi.Pointer<ffi.Uint8> ptr, int len) {
    if (ptr == ffi.nullptr || len == 0) return const [];
    final bytes = ptr.asTypedList(len).toList(growable: false);
    _bufferFree(ptr, len);
    return bytes;
  }

  static ({ffi.Pointer<ffi.Uint8> ptr, int len}) _copy(
    ffi.Allocator arena,
    List<int> bytes,
  ) {
    if (bytes.isEmpty) {
      return (ptr: ffi.nullptr, len: 0);
    }
    final ptr = arena<ffi.Uint8>(bytes.length);
    ptr.asTypedList(bytes.length).setAll(0, bytes);
    return (ptr: ptr, len: bytes.length);
  }

  static Uint8List _encodeRecipients(List<List<int>> keys) {
    var total = 4;
    for (final k in keys) {
      total += 4 + k.length;
    }
    final out = ByteData(total);
    var o = 0;
    out.setUint32(o, keys.length, Endian.big);
    o += 4;
    for (final k in keys) {
      out.setUint32(o, k.length, Endian.big);
      o += 4;
      out.buffer.asUint8List().setRange(o, o + k.length, k);
      o += k.length;
    }
    return out.buffer.asUint8List();
  }

  static ffi.DynamicLibrary _open() {
    final override = Platform.environment['SCOMM_OPENPGP_LIB'];
    if (override != null && override.isNotEmpty) {
      return ffi.DynamicLibrary.open(override);
    }
    if (Platform.isWindows) {
      return ffi.DynamicLibrary.open('scomm_openpgp.dll');
    }
    if (Platform.isLinux) {
      return ffi.DynamicLibrary.open('libscomm_openpgp.so');
    }
    if (Platform.isMacOS || Platform.isIOS) {
      return ffi.DynamicLibrary.open('libscomm_openpgp.dylib');
    }
    if (Platform.isAndroid) {
      return ffi.DynamicLibrary.open('libscomm_openpgp.so');
    }
    throw UnsupportedError(
      'scomm_openpgp has no bundled library for ${Platform.operatingSystem}',
    );
  }
}
