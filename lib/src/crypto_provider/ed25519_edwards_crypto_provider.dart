import 'dart:async';
import 'dart:typed_data';

import 'package:ed25519_edwards/ed25519_edwards.dart' as ed;
import 'package:sd_jwt/src/sd_jwt_crypto_provider.dart';
import 'package:sd_jwt/src/sd_jwt_jwk.dart';

/// Software Crypto Provider for EdDSA Signatures with Curve ed25519
class Ed25519EdwardsCryptoProvider implements CryptoProvider {
  final AsymmetricKey? key;

  Ed25519EdwardsCryptoProvider([this.key]);

  @override
  Uint8List digest(
      {required Uint8List data, required DigestAlgorithm algorithm}) {
    throw UnimplementedError();
  }

  @override
  Key generateKeyPair({required KeyParameters keyParameters, Uint8List? seed}) {
    if (keyParameters is EcKeyParameters &&
        keyParameters.curve == Curve.curve25519) {
      if (seed != null) {
        ed.PrivateKey privateKey = ed.newKeyFromSeed(seed);
        ed.PublicKey publicKey = ed.public(privateKey);
        return EdPrivateKey(
          a: Uint8List.fromList(ed.seed(privateKey)),
          pubA: Uint8List.fromList(publicKey.bytes),
          curve: keyParameters.curve,
        );
      } else {
        ed.KeyPair keyPair = ed.generateKey();

        return EdPrivateKey(
            a: Uint8List.fromList(ed.seed(keyPair.privateKey)),
            pubA: Uint8List.fromList(keyPair.publicKey.bytes),
            curve: keyParameters.curve);
      }
    } else {
      throw Exception('Key parameters not supported by this implementation.');
    }
  }

  @override
  String get name => 'ed25519_edwards';

  @override
  FutureOr<Signature> sign(
      {required Uint8List data, required SigningAlgorithm algorithm}) {
    ed.PrivateKey privateKey = ed.newKeyFromSeed((key as PrivateKey).private);
    Uint8List signatureBytes = ed.sign(privateKey, data);
    Signature signature = EcSignature(
        signatureBytes.sublist(0, (signatureBytes.length / 2).truncate()),
        signatureBytes.sublist((signatureBytes.length / 2).truncate()));
    return signature;
  }

  @override
  bool verify(
      {required Uint8List data,
      required SigningAlgorithm algorithm,
      required Signature signature}) {
    ed.PublicKey publicKey = ed.PublicKey((key as EdPublicKey).pubA);
    return ed.verify(publicKey, data,
        Uint8List.fromList((signature as EcSignature).r + signature.s));
  }
}
