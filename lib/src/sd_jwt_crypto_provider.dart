import 'dart:async';
import 'dart:typed_data';

import 'package:sd_jwt/src/sd_jwt_jwk.dart';

abstract class CryptoProvider {
  final String name = '';

  AsymmetricKey generateEcKeyPair({required Curve curve});

  Uint8List digest(
      {required Uint8List data, required DigestAlgorithm algorithm});

  FutureOr<Uint8List> sign(
      {required Uint8List data, required SigningAlgorithm algorithm});

  bool verify(
      {required Uint8List data,
      required SigningAlgorithm algorithm,
      required Signature signature});
}

enum SigningAlgorithm {
  ecdsaSha256Prime,
  ecdsaSha256Koblitz,
  ecdsaSha256KoblitzRecovery,
  ecdsaSha384Prime,
  ecdsaSha512Prime,
}

enum DigestAlgorithm { sha2_256, sha2_384, sha2_512, sha3_256 }

extension SdAlgorithmName on DigestAlgorithm {
  String get name {
    switch (this) {
      case DigestAlgorithm.sha2_256:
        return 'sha-256';
      case DigestAlgorithm.sha2_384:
        return 'sha-384';
      case DigestAlgorithm.sha2_512:
        return 'sha-512';
      case DigestAlgorithm.sha3_256:
        return 'sha3-256';
    }
  }
}

extension DigestAlgorithmName on SigningAlgorithm {
  String get digest {
    switch (this) {
      case SigningAlgorithm.ecdsaSha256Prime:
        return 'SHA-256';
      case SigningAlgorithm.ecdsaSha256Koblitz:
        return 'SHA-256';
      case SigningAlgorithm.ecdsaSha256KoblitzRecovery:
        return 'SHA-256';
      case SigningAlgorithm.ecdsaSha384Prime:
        return 'SHA-384';
      case SigningAlgorithm.ecdsaSha512Prime:
        return 'SHA-512';
    }
  }
}

extension DigestAlgorithmLength on SigningAlgorithm {
  int get digestLength {
    switch (this) {
      case SigningAlgorithm.ecdsaSha256Prime:
        return 256;
      case SigningAlgorithm.ecdsaSha256Koblitz:
        return 256;
      case SigningAlgorithm.ecdsaSha256KoblitzRecovery:
        return 256;
      case SigningAlgorithm.ecdsaSha384Prime:
        return 384;
      case SigningAlgorithm.ecdsaSha512Prime:
        return 512;
    }
  }
}

extension JWA on SigningAlgorithm {
  String get name {
    switch (this) {
      case SigningAlgorithm.ecdsaSha256Prime:
        return 'ES256';
      case SigningAlgorithm.ecdsaSha256Koblitz:
        return 'ES256K';
      case SigningAlgorithm.ecdsaSha256KoblitzRecovery:
        return 'ES256K-R';
      case SigningAlgorithm.ecdsaSha384Prime:
        return 'ES384';
      case SigningAlgorithm.ecdsaSha512Prime:
        return 'ES512';
    }
  }

  String get description {
    switch (this) {
      case SigningAlgorithm.ecdsaSha256Prime:
        return 'ECDSA using P-256 and SHA-256';
      case SigningAlgorithm.ecdsaSha256Koblitz:
        return 'ECDSA using P-256K and SHA-256';
      case SigningAlgorithm.ecdsaSha256KoblitzRecovery:
        return 'ECDSA using P-256K with public key recovery and SHA-256';
      case SigningAlgorithm.ecdsaSha384Prime:
        return 'ECDSA using P-384 and SHA-384';
      case SigningAlgorithm.ecdsaSha512Prime:
        return 'ECDSA using P-521 and SHA-512';
    }
  }
}

enum Curve {
  p256,
  p256k,
  p384,
  p521,
}

extension CurveName on Curve {
  String get name {
    switch (this) {
      case Curve.p256:
        return 'P-256';
      case Curve.p256k:
        return 'P-256K';
      case Curve.p384:
        return 'P-384';
      case Curve.p521:
        return 'P-521';
    }
  }

  int get length {
    switch (this) {
      case Curve.p256:
        return 256;
      case Curve.p256k:
        return 256;
      case Curve.p384:
        return 384;
      case Curve.p521:
        return 521;
    }
  }
}

abstract class Signature {}

class EcSignature implements Signature {
  Uint8List r;
  Uint8List s;

  EcSignature(this.r, this.s);
}

class RsaSignature implements Signature {}
