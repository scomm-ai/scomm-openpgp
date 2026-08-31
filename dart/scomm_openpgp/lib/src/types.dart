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
  });

  final String fingerprint;
  final String keyId;
  final String algorithm;
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
    this.createdAt,
    this.expiresAt,
  });

  final String fingerprint;
  final String keyId;
  final String algorithm;
  final int? createdAt;
  final int? expiresAt;
  final bool revoked;
  final bool hasSecret;
  final bool secretEncrypted;
  final List<String> capabilities;
  final List<OpenPgpIdentityInfo> identities;
  final List<OpenPgpSubkeyInspect> subkeys;

  factory OpenPgpKeyInspect.fromJson(Map<String, dynamic> json) {
    return OpenPgpKeyInspect(
      fingerprint: json['fingerprint'] as String? ?? '',
      keyId: json['key_id'] as String? ?? '',
      algorithm: json['algorithm'] as String? ?? '',
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

List<String> _stringList(Object? raw) {
  if (raw is! List) return const [];
  return [for (final e in raw) e.toString()];
}
