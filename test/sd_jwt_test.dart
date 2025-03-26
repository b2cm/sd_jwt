import 'package:sd_jwt/sd_jwt.dart';
import 'package:test/test.dart';

void main() {
  group('Basic tests', () {
    setUp(() {
      // Additional setup goes here.
    });

    test('Sign with own key', () async {
      Jwk jsonWebKey = Jwk(
          keyType: KeyType.ec,
          key: EcPrivateKey.generate(Curve.p256k),
          algorithm: SigningAlgorithm.ecdsaSha256Koblitz);
      var awesome = Jwt(additionalClaims: {'vc': 'VerifiableCredential'});
      Jws sdJws = await awesome.sign(
          signingAlgorithm: SigningAlgorithm.ecdsaSha256Koblitz,
          signer: PointyCastleCryptoProvider(jsonWebKey.key as EcPrivateKey));
      print(sdJws.toCompactSerialization());
      print(sdJws.toJson());
      expect(
          sdJws.verify(PointyCastleCryptoProvider(
              Jwk.fromJson(jsonWebKey.toJson()).key as EcPrivateKey)),
          isTrue);
    });
  });

  group('Default algorithms', () {
    setUp(() {});

    test('ECDSA using P-256 and SHA-256', () async {
      Jws sdJws = await _generateSdJws(
          KeyType.ec, Curve.p256, SigningAlgorithm.ecdsaSha256Prime);
    });
    test('ECDSA using P-256K and SHA-256', () async {
      Jws sdJws = await _generateSdJws(
          KeyType.ec, Curve.p256k, SigningAlgorithm.ecdsaSha256Koblitz);
    });
    test('ECDSA using P-384 and SHA-384', () async {
      Jws sdJws = await _generateSdJws(
          KeyType.ec, Curve.p384, SigningAlgorithm.ecdsaSha384Prime);
    });
    test('ECDSA using P-521 and SHA-512', () async {
      Jws sdJws = await _generateSdJws(
        KeyType.ec,
        Curve.p521,
        SigningAlgorithm.ecdsaSha512Prime,
      );
    });
  });
  group('All algorithms', () {
    setUp(() {});

    test('ECDSA using P-256 and SHA-256', () async {
      Jws sdJws = await _generateSdJws(
          KeyType.ec, Curve.p256, SigningAlgorithm.ecdsaSha256Prime);
    });

    test('ECDSA using P-256 and SHA-256K', () async {
      Jws sdJws = await _generateSdJws(
          KeyType.ec, Curve.p256, SigningAlgorithm.ecdsaSha256Koblitz);
    });

    test('ECDSA using P-256 and SHA-384', () async {
      try {
        Jws sdJws = await _generateSdJws(
            KeyType.ec, Curve.p256, SigningAlgorithm.ecdsaSha384Prime);
      } catch (e) {
        print(e);
        expect(e.toString(),
            'Exception: Curve cardinality is smaller than digest length, that\'s not possible.');
      }
    });

    test('ECDSA using P-256 and SHA-512', () async {
      try {
        Jws sdJws = await _generateSdJws(
            KeyType.ec, Curve.p256, SigningAlgorithm.ecdsaSha384Prime);
      } catch (e) {
        print(e);
        expect(e.toString(),
            'Exception: Curve cardinality is smaller than digest length, that\'s not possible.');
      }
    });

    test('ECDSA using P-256K and SHA-256', () async {
      Jws sdJws = await _generateSdJws(
          KeyType.ec, Curve.p256k, SigningAlgorithm.ecdsaSha256Prime);
    });

    test('ECDSA using P-256K and SHA-256K', () async {
      Jws sdJws = await _generateSdJws(
          KeyType.ec, Curve.p256k, SigningAlgorithm.ecdsaSha256Koblitz);
    });

    test('ECDSA using P-256K and SHA-384', () async {
      try {
        Jws sdJws = await _generateSdJws(
            KeyType.ec, Curve.p256k, SigningAlgorithm.ecdsaSha384Prime);
      } catch (e) {
        print(e);
        expect(e.toString(),
            'Exception: Curve cardinality is smaller than digest length, that\'s not possible.');
      }
    });

    test('ECDSA using P-256K and SHA-512', () async {
      try {
        Jws sdJws = await _generateSdJws(
            KeyType.ec, Curve.p256k, SigningAlgorithm.ecdsaSha512Prime);
      } catch (e) {
        print(e);
        expect(e.toString(),
            'Exception: Curve cardinality is smaller than digest length, that\'s not possible.');
      }
    });

    test('ECDSA using P-384 and SHA-256', () async {
      Jws sdJws = await _generateSdJws(
          KeyType.ec, Curve.p384, SigningAlgorithm.ecdsaSha256Prime);
    });

    test('ECDSA using P-384 and SHA-256K', () async {
      Jws sdJws = await _generateSdJws(
          KeyType.ec, Curve.p384, SigningAlgorithm.ecdsaSha256Koblitz);
    });

    test('ECDSA using P-384 and SHA-384', () async {
      Jws sdJws = await _generateSdJws(
          KeyType.ec, Curve.p384, SigningAlgorithm.ecdsaSha384Prime);
    });

    test('ECDSA using P-384 and SHA-512', () async {
      try {
        Jws sdJws = await _generateSdJws(
            KeyType.ec, Curve.p384, SigningAlgorithm.ecdsaSha512Prime);
      } catch (e) {
        print(e);
        expect(e.toString(),
            'Exception: Curve cardinality is smaller than digest length, that\'s not possible.');
      }
    });

    test('ECDSA using P-521 and SHA-256', () async {
      Jws sdJws = await _generateSdJws(
          KeyType.ec, Curve.p521, SigningAlgorithm.ecdsaSha256Prime);
    });

    test('ECDSA using P-521 and SHA-256K', () async {
      Jws sdJws = await _generateSdJws(
          KeyType.ec, Curve.p521, SigningAlgorithm.ecdsaSha256Koblitz);
    });

    test('ECDSA using P-521 and SHA-384', () async {
      Jws sdJws = await _generateSdJws(
        KeyType.ec,
        Curve.p521,
        SigningAlgorithm.ecdsaSha384Prime,
      );
    });

    test('ECDSA using P-521 and SHA-512', () async {
      Jws sdJws = await _generateSdJws(
        KeyType.ec,
        Curve.p521,
        SigningAlgorithm.ecdsaSha512Prime,
      );
    });
  });
}

Future<Jws> _generateSdJws(
    KeyType keyType, Curve curve, SigningAlgorithm algorithm) async {
  Jwk jsonWebKey = Jwk(
      keyType: keyType,
      key: EcPrivateKey.generate(curve),
      algorithm: algorithm);
  var awesome = Jwt(additionalClaims: {'vc': 'VerifiableCredential'});
  Jws sdJws = await awesome.sign(
      signingAlgorithm: algorithm,
      signer: PointyCastleCryptoProvider(jsonWebKey.key as EcPrivateKey));
  print(sdJws.toCompactSerialization());
  print(sdJws.toJson());
  expect(
      sdJws.verify(PointyCastleCryptoProvider(
          Jwk.fromJson(jsonWebKey.toJson()).key as EcPrivateKey)),
      isTrue);
  return sdJws;
}
