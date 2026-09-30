class ScommOpenPgpException implements Exception {
  ScommOpenPgpException(this.code, this.message);

  final int code;
  final String message;

  @override
  String toString() => 'ScommOpenPgpException($code): $message';
}

class OpenPgpIdentityInfo {
  const OpenPgpIdentityInfo({this.name, this.email});

  final String? name;
  final String? email;
}

class OpenPgpSubkeyInspect {
  const OpenPgpSubkeyInspect({
    required this.fingerprint,
    required this.keyId,
    required this.algorithm,
    required this.capabilities,
    this.algorithmId = 0,
  });

  final String fingerprint;
  final String keyId;
  final String algorithm;
  final int algorithmId;
  final List<String> capabilities;
}

class OpenPgpKeyInspect {
  const OpenPgpKeyInspect({
    required this.fingerprint,
    required this.keyId,
    required this.algorithm,
    required this.revoked,
    required this.hasSecret,
    required this.secretEncrypted,
    required this.capabilities,
    required this.identities,
    required this.subkeys,
    this.algorithmId = 0,
    this.createdAt,
    this.expiresAt,
  });

  final String fingerprint;
  final String keyId;
  final String algorithm;
  final int algorithmId;
  final int? createdAt;
  final int? expiresAt;
  final bool revoked;
  final bool hasSecret;
  final bool secretEncrypted;
  final List<String> capabilities;
  final List<OpenPgpIdentityInfo> identities;
  final List<OpenPgpSubkeyInspect> subkeys;

  static bool _isRfc9980(int id) => id >= 30 && id <= 36;

  bool get isPqc =>
      _isRfc9980(algorithmId) ||
      subkeys.any((s) => _isRfc9980(s.algorithmId)) ||
      algorithm.toLowerCase().contains('mldsa') ||
      algorithm.toLowerCase().contains('mlkem') ||
      subkeys.any(
        (s) =>
            s.algorithm.toLowerCase().contains('mldsa') ||
            s.algorithm.toLowerCase().contains('mlkem'),
      );

  bool get isPqcSigning =>
      (algorithmId >= 30 && algorithmId <= 34) ||
      algorithm.toLowerCase().startsWith('openpgp-mldsa') ||
      algorithm.toLowerCase().startsWith('openpgp-slhdsa');

  factory OpenPgpKeyInspect.fromJson(Map<String, dynamic> json) {
    return OpenPgpKeyInspect(
      fingerprint: json['fingerprint'] as String? ?? '',
      keyId: json['key_id'] as String? ?? '',
      algorithm: json['algorithm'] as String? ?? '',
      algorithmId: (json['algorithm_id'] as num?)?.toInt() ?? 0,
      createdAt: (json['created_at'] as num?)?.toInt(),
      expiresAt: (json['expires_at'] as num?)?.toInt(),
      revoked: json['revoked'] as bool? ?? false,
      hasSecret: json['has_secret'] as bool? ?? false,
      secretEncrypted: json['secret_encrypted'] as bool? ?? false,
      capabilities: _stringList(json['capabilities']),
      identities: [
        for (final raw in json['identities'] as List? ?? const [])
          if (raw is Map)
            OpenPgpIdentityInfo(
              name: raw['name'] as String?,
              email: raw['email'] as String?,
            ),
      ],
      subkeys: [
        for (final raw in json['subkeys'] as List? ?? const [])
          if (raw is Map)
            OpenPgpSubkeyInspect(
              fingerprint: raw['fingerprint'] as String? ?? '',
              keyId: raw['key_id'] as String? ?? '',
              algorithm: raw['algorithm'] as String? ?? '',
              algorithmId: (raw['algorithm_id'] as num?)?.toInt() ?? 0,
              capabilities: _stringList(raw['capabilities']),
            ),
      ],
    );
  }
}

class GeneratedOpenPgpKey {
  const GeneratedOpenPgpKey({
    required this.public,
    required this.secret,
    required this.info,
  });

  final List<int> public;
  final List<int> secret;
  final OpenPgpKeyInspect info;
}

/// Generate profile. Matches C ABI `profile` on `scomm_openpgp_generate`.
enum OpenPgpKeyProfile {
  classicalCv25519(0),
  rfc9980MlDsa65(1),

  /// RFC 9580 Ed25519/X25519. Personal Security default when the native
  /// library accepts profile id 2.
  rfc9580Classical(2);

  const OpenPgpKeyProfile(this.wire);
  final int wire;
}

List<String> _stringList(Object? raw) {
  if (raw is! List) return const [];
  return [for (final e in raw) e.toString()];
}
