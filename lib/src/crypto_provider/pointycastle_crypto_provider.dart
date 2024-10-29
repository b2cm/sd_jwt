import 'dart:math';
import 'dart:typed_data';

import 'package:pointycastle/export.dart' as pointy_castle;
import 'package:sd_jwt/src/sd_jwt_crypto_provider.dart';
import 'package:sd_jwt/src/sd_jwt_jwk.dart';

import '../sd_jwt_utils.dart';

class PointyCastleCryptoProvider implements CryptoProvider {
  @override
  String get name => 'pointy_castle';
  final AsymmetricKey? key;

  PointyCastleCryptoProvider([this.key]);

  @override
  Signature sign(
      {required Uint8List data, required SigningAlgorithm algorithm}) {
    if (key is! PrivateKey) {
      throw Exception('private key needed for signing');
    }
    var privateKey = key as PrivateKey;

    if (privateKey is EcPrivateKey) {
      if (algorithm.digestLength > privateKey.curve.length) {
        throw Exception(
            'Curve cardinality is smaller than digest length, that\'s not possible.');
      }
      pointy_castle.ECDomainParameters ecDomainParameters =
          _getECDomainParameters(privateKey.curve);
      pointy_castle.Digest digest = _getDigest(algorithm);

      int length = {
        Curve.p256: 32,
        Curve.p256k: 32,
        Curve.p384: 48,
        Curve.p521: 66
      }[privateKey.curve]!;

      pointy_castle.ECDSASigner ecdsaSigner =
          pointy_castle.ECDSASigner(digest, pointy_castle.HMac(digest, length));
      pointy_castle.ECPrivateKey key = pointy_castle.ECPrivateKey(
          uInt8ListToBigInt(privateKey.private), ecDomainParameters);

      ecdsaSigner.init(
          true,
          pointy_castle.ParametersWithRandom(
              pointy_castle.PrivateKeyParameter(key), DefaultSecureRandom()));

      pointy_castle.ECSignature signature =
          ecdsaSigner.generateSignature(data) as pointy_castle.ECSignature;

      // Uint8List bytes = Uint8List(length * 2);
      // bytes.setRange(
      //     0, length, bigIntToBytes(signature.r, length).toList().reversed);
      // bytes.setRange(length, length * 2,
      //     bigIntToBytes(signature.s, length).toList().reversed);
      //
      // return bytes;

      return EcSignature(
          Uint8List.fromList(bigIntToBytes(signature.r, length).toList().reversed.toList()),
          Uint8List.fromList(bigIntToBytes(signature.s, length).toList().reversed.toList())
      );
    }
    throw Exception('Key type not supported.');
  }

  @override
  bool verify(
      {required Uint8List data,
      required SigningAlgorithm algorithm,
      required Signature signature}) {
    PublicKey publicKey;
    if (key is PrivateKey) {
      publicKey = key!.public;
    } else if (key is PublicKey) {
      publicKey = key as PublicKey;
    } else {
      throw Exception('No key given');
    }

    if (publicKey is EcPublicKey) {
      if (algorithm.digestLength > publicKey.curve.length) {
        throw Exception(
            'Curve cardinality is smaller than digest length, that\'s not possible.');
      }
      pointy_castle.ECDomainParameters ecDomainParameters =
          _getECDomainParameters(publicKey.curve);
      pointy_castle.ECPoint point = ecDomainParameters.curve.createPoint(
          uInt8ListToBigInt((publicKey).x), uInt8ListToBigInt((publicKey).y));
      pointy_castle.ECPublicKey key =
          pointy_castle.ECPublicKey(point, ecDomainParameters);

      pointy_castle.Digest digest = _getDigest(algorithm);

      int length = {
        Curve.p256: 32,
        Curve.p256k: 32,
        Curve.p384: 48,
        Curve.p521: 66
      }[publicKey.curve]!;

      pointy_castle.ECDSASigner ecdsaSigner =
          pointy_castle.ECDSASigner(digest, pointy_castle.HMac(digest, length));

      ecdsaSigner.init(false, pointy_castle.PublicKeyParameter(key));

      pointy_castle.ECSignature ecSignature = pointy_castle.ECSignature(
          uInt8ListToBigInt((signature as EcSignature).r),
          uInt8ListToBigInt((signature.s)));

      return ecdsaSigner.verifySignature(data, ecSignature);
    }
    throw Exception('Key type not supported.');
  }

  @override
  Key generateKeyPair({required KeyParameters keyParameters}) {

    if(keyParameters is EcKeyParameters) {
      keyParameters as EcKeyParameters;
      pointy_castle.ECDomainParameters ecDomainParameters =
      _getECDomainParameters(keyParameters.curve);

      pointy_castle.ECKeyGenerator ecKeyGenerator =
      pointy_castle.ECKeyGenerator();

      ecKeyGenerator.init(pointy_castle.ParametersWithRandom(
          pointy_castle.ECKeyGeneratorParameters(ecDomainParameters),
          DefaultSecureRandom()));
      pointy_castle
          .AsymmetricKeyPair<pointy_castle.PublicKey, pointy_castle.PrivateKey>
      asymmetricKeyPair = ecKeyGenerator.generateKeyPair();
      pointy_castle.ECPrivateKey privateKey =
      asymmetricKeyPair.privateKey as pointy_castle.ECPrivateKey;
      pointy_castle.ECPublicKey publicKey =
      asymmetricKeyPair.publicKey as pointy_castle.ECPublicKey;
      return EcPrivateKey(
          x: bigIntToUInt8List(publicKey.Q!.x!.toBigInteger()!),
          y: bigIntToUInt8List(publicKey.Q!.y!.toBigInteger()!),
          d: bigIntToUInt8List(privateKey.d!),
          curve: keyParameters.curve);
    } else {
      throw Exception();
    }
  }

  pointy_castle.ECDomainParameters _getECDomainParameters(Curve curve) {
    switch (curve) {
      case Curve.p256:
        return pointy_castle.ECCurve_secp256r1();
      case Curve.p256k:
        return pointy_castle.ECCurve_secp256k1();
      case Curve.p384:
        return pointy_castle.ECCurve_secp384r1();
      case Curve.p521:
        return pointy_castle.ECCurve_secp521r1();
      case Curve.curve25519:
        throw Exception('Curve not supported by this implementation.');
    }
  }

  pointy_castle.Digest _getDigest(SigningAlgorithm algorithm) {
    switch (algorithm) {
      case SigningAlgorithm.ecdsaSha256Prime:
        return pointy_castle.SHA256Digest();
      case SigningAlgorithm.ecdsaSha256Koblitz:
        return pointy_castle.SHA256Digest();
      case SigningAlgorithm.ecdsaSha384Prime:
        return pointy_castle.SHA384Digest();
      case SigningAlgorithm.ecdsaSha512Prime:
        return pointy_castle.SHA512Digest();
      case SigningAlgorithm.ecdsaSha256KoblitzRecovery:
        return pointy_castle.SHA256Digest();
      default:
        throw Exception('Signing algorithm not supported by this implementation.');
    }
  }

  @override
  Uint8List digest(
      {required Uint8List data, required DigestAlgorithm algorithm}) {
    pointy_castle.Digest digest;
    switch (algorithm) {
      case DigestAlgorithm.sha2_256:
        digest = pointy_castle.SHA256Digest();
      case DigestAlgorithm.sha2_384:
        digest = pointy_castle.SHA384Digest();
      case DigestAlgorithm.sha2_512:
        digest = pointy_castle.SHA512Digest();
      case DigestAlgorithm.sha3_256:
        digest = pointy_castle.SHA3Digest(256);
    }
    return digest.process(data);
  }
}

class DefaultSecureRandom implements pointy_castle.SecureRandom {
  final Random random = Random.secure();

  @override
  String get algorithmName => 'dart.math.Random.secure()';

  @override
  BigInt nextBigInteger(int bitLength) {
    return BigInt.parse(
        Iterable.generate(bitLength, (_) => random.nextBool() ? '1' : '0')
            .join(''),
        radix: 2);
  }

  @override
  Uint8List nextBytes(int count) =>
      Uint8List.fromList(List.generate(count, (_) => nextUint8()));

  @override
  int nextUint16() => random.nextInt(256 * 256);

  @override
  int nextUint32() => random.nextInt(256 * 256 * 256 * 256);

  @override
  int nextUint8() => random.nextInt(256);

  @override
  void seed(pointy_castle.CipherParameters params) {
    throw UnsupportedError('Seed not supported for this SecureRandom');
  }
}
