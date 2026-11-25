// Run with a shared library built from this SDK in SCOMM_OPENPGP_LIB.
import 'dart:convert';
import '../lib/scomm_openpgp.dart';

void main(List<String> args) {
  final sdk = ScommOpenPgp.instance;
  if (args.contains('--expect-unsupported')) {
    if (sdk.supportsNistCurves) throw StateError('Expected an older library');
    try {
      sdk.generateKey(
          userid: 'curves@example.com',
          profile: OpenPgpKeyProfile.classicalP256);
    } on UnsupportedError {
      print('Older OpenPGP library correctly refused NIST curves');
      return;
    }
    throw StateError('Older library did not reject NIST curves');
  }
  if (!sdk.supportsNistCurves) throw StateError('OpenPGP ABI 7 required');
  final data = utf8.encode('Dart native NIST curves');
  for (final profile in OpenPgpKeyProfile.values.where((p) => p.wire >= 3)) {
    final key = sdk.generateKey(
        userid: 'Curves <curves@example.com>',
        profile: profile,
        validityYears: 2);
    final sig = sdk.signDetached(data: data, privateKey: key.secret);
    if (!sdk.verifyDetached(data: data, signature: sig, publicKey: key.public))
      throw StateError('Signature failed: $profile');
    final encrypted =
        sdk.encrypt(plaintext: data, recipientPublicKeys: [key.public]);
    if (utf8.decode(
            sdk.decrypt(ciphertext: encrypted, privateKey: key.secret)) !=
        utf8.decode(data)) throw StateError('Decryption failed: $profile');
    print('OpenPGP $profile passed');
  }
}
