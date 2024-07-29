import 'package:sd_jwt/sd_jwt.dart';
import 'package:sd_jwt/src/sd_jwt_crypto_provider.dart';
import 'package:sd_jwt/src/sd_jwt_jwk.dart';
import 'package:sd_jwt/src/sd_jwt_jws.dart';
import 'package:test/test.dart';
import 'package:jose/jose.dart';

void main() {
  group('Basic tests', () {
    setUp(() {
      // Additional setup goes here.
    });

    test('Sign with external key', () async {
      JsonWebKeyStore jsonWebKeyStore = JsonWebKeyStore();
      JsonWebKey jsonWebKey = JsonWebKey.generate(JsonWebAlgorithm.es256k.name);
      jsonWebKeyStore.addKey(jsonWebKey);
      var awesome = Jwt(claims: {
        'vc': 'VerifiableCredential'
        // }, jsonWebKey: Jwk.fromJson(jsonWebKey.toJson()));
      });
      Jws sdJws = awesome.sign(jsonWebKey: Jwk.fromJson(jsonWebKey.toJson()));
      print(sdJws.toCompactSerialization());
      print(sdJws.toJson());
      JsonWebSignature jsonWebSignature =
          JsonWebSignature.fromCompactSerialization(
              sdJws.toCompactSerialization().split('~').first);
      print(await jsonWebSignature.verify(jsonWebKeyStore));
      expect(await jsonWebSignature.verify(jsonWebKeyStore), isTrue);
    });

    test('Sign with own key', () async {
      JsonWebKeyStore jsonWebKeyStore = JsonWebKeyStore();
      Jwk jsonWebKey = Jwk(
          keyType: KeyType.ec,
          key: EcPrivateKey.generate(Curve.p256k),
          algorithm: SigningAlgorithm.ecdsaSha256Koblitz);
      jsonWebKeyStore.addKey(JsonWebKey.fromJson(jsonWebKey.toJson()));
      var awesome = Jwt(claims: {
        'vc': 'VerifiableCredential'
        // }, jsonWebKey: Jwk.fromJson(jsonWebKey.toJson()));
      });
      Jws sdJws = awesome.sign(jsonWebKey: jsonWebKey);
      print(sdJws.toCompactSerialization());
      print(sdJws.toJson());
      JsonWebSignature jsonWebSignature =
          JsonWebSignature.fromCompactSerialization(
              sdJws.toCompactSerialization().split('~').first);
      print(await jsonWebSignature.verify(jsonWebKeyStore));
      expect(await jsonWebSignature.verify(jsonWebKeyStore), isTrue);
    });
  });

  group('Default algorithms', () {
    setUp(() {

    });

    test('ECDSA using P-256 and SHA-256', () async {
      JsonWebKeyStore jsonWebKeyStore = JsonWebKeyStore();
      Jws sdJws = _generateSdJws(KeyType.ec, Curve.p256, SigningAlgorithm.ecdsaSha256Prime, jsonWebKeyStore);
      bool result = await _verifySdJws(
          sdJws,
          jsonWebKeyStore);
      expect(
          result,
          isTrue);
    });
    test('ECDSA using P-256K and SHA-256', () async {
      JsonWebKeyStore jsonWebKeyStore = JsonWebKeyStore();
      Jws sdJws = _generateSdJws(KeyType.ec, Curve.p256k, SigningAlgorithm.ecdsaSha256Koblitz, jsonWebKeyStore);
      expect(
          await _verifySdJws(
          sdJws,
          jsonWebKeyStore),
      isTrue);
    });
    test('ECDSA using P-384 and SHA-384', () async {
      JsonWebKeyStore jsonWebKeyStore = JsonWebKeyStore();
      Jws sdJws = _generateSdJws(KeyType.ec, Curve.p384, SigningAlgorithm.ecdsaSha384Prime, jsonWebKeyStore);
      expect(
          await _verifySdJws(
          sdJws,
          jsonWebKeyStore),
      isTrue);
    });
    test('ECDSA using P-521 and SHA-512', () async {
      JsonWebKeyStore jsonWebKeyStore = JsonWebKeyStore();
      Jws sdJws = _generateSdJws(KeyType.ec, Curve.p521, SigningAlgorithm.ecdsaSha512Prime, jsonWebKeyStore);
      expect(
          await _verifySdJws(
          sdJws,
          jsonWebKeyStore),
      isTrue);
    });
  });
  group('All algorithms', () {
    setUp(() {

    });

    test('ECDSA using P-256 and SHA-256', () async {
      JsonWebKeyStore jsonWebKeyStore = JsonWebKeyStore();
      Jws sdJws = _generateSdJws(KeyType.ec, Curve.p256, SigningAlgorithm.ecdsaSha256Prime, jsonWebKeyStore);
      bool result = await _verifySdJws(
          sdJws,
          jsonWebKeyStore);
      expect(
          result,
          isTrue);
    });

    test('ECDSA using P-256 and SHA-256K', () async {
      JsonWebKeyStore jsonWebKeyStore = JsonWebKeyStore();
      Jws sdJws = _generateSdJws(KeyType.ec, Curve.p256, SigningAlgorithm.ecdsaSha256Koblitz, jsonWebKeyStore);
      bool result = await _verifySdJws(
          sdJws,
          jsonWebKeyStore);
      expect(
          result,
          isTrue);
    });

    test('ECDSA using P-256 and SHA-384', () async {
      JsonWebKeyStore jsonWebKeyStore = JsonWebKeyStore();
      try {
        Jws sdJws = _generateSdJws(KeyType.ec, Curve.p256, SigningAlgorithm.ecdsaSha384Prime, jsonWebKeyStore);
        await _verifySdJws(sdJws, jsonWebKeyStore);
      } catch (e){
        print(e);
        expect(e.toString(), 'Exception: Curve cardinality is smaller than digest length, that\'s not possible.');
      }
    });

    test('ECDSA using P-256 and SHA-512', () async {
      JsonWebKeyStore jsonWebKeyStore = JsonWebKeyStore();
      try {
        Jws sdJws = _generateSdJws(KeyType.ec, Curve.p256, SigningAlgorithm.ecdsaSha384Prime, jsonWebKeyStore);
        await _verifySdJws(sdJws, jsonWebKeyStore);
      } catch (e){
        print(e);
        expect(e.toString(), 'Exception: Curve cardinality is smaller than digest length, that\'s not possible.');
      }
    });

    test('ECDSA using P-256K and SHA-256', () async {
      JsonWebKeyStore jsonWebKeyStore = JsonWebKeyStore();
      Jws sdJws = _generateSdJws(KeyType.ec, Curve.p256k, SigningAlgorithm.ecdsaSha256Prime, jsonWebKeyStore);
      expect(
          await _verifySdJws(
              sdJws,
              jsonWebKeyStore),
          isTrue);
    });

    test('ECDSA using P-256K and SHA-256K', () async {
      JsonWebKeyStore jsonWebKeyStore = JsonWebKeyStore();
      Jws sdJws = _generateSdJws(KeyType.ec, Curve.p256k, SigningAlgorithm.ecdsaSha256Koblitz, jsonWebKeyStore);
      expect(
          await _verifySdJws(
              sdJws,
              jsonWebKeyStore),
          isTrue);
    });

    test('ECDSA using P-256K and SHA-384', () async {
      JsonWebKeyStore jsonWebKeyStore = JsonWebKeyStore();
      try {
        Jws sdJws = _generateSdJws(KeyType.ec, Curve.p256k, SigningAlgorithm.ecdsaSha384Prime, jsonWebKeyStore);
        await _verifySdJws(sdJws, jsonWebKeyStore);
      } catch (e){
        print(e);
        expect(e.toString(), 'Exception: Curve cardinality is smaller than digest length, that\'s not possible.');
      }

    });

    test('ECDSA using P-256K and SHA-512', () async {
      JsonWebKeyStore jsonWebKeyStore = JsonWebKeyStore();
      try {
        Jws sdJws = _generateSdJws(KeyType.ec, Curve.p256k, SigningAlgorithm.ecdsaSha512Prime, jsonWebKeyStore);
        await _verifySdJws(sdJws, jsonWebKeyStore);
      } catch (e){
        print(e);
        expect(e.toString(), 'Exception: Curve cardinality is smaller than digest length, that\'s not possible.');
      }
    });

    test('ECDSA using P-384 and SHA-256', () async {
      JsonWebKeyStore jsonWebKeyStore = JsonWebKeyStore();
      Jws sdJws = _generateSdJws(KeyType.ec, Curve.p384, SigningAlgorithm.ecdsaSha256Prime, jsonWebKeyStore);
      expect(
          await _verifySdJws(
              sdJws,
              jsonWebKeyStore),
          isTrue);
    });

    test('ECDSA using P-384 and SHA-256K', () async {
      JsonWebKeyStore jsonWebKeyStore = JsonWebKeyStore();
      Jws sdJws = _generateSdJws(KeyType.ec, Curve.p384, SigningAlgorithm.ecdsaSha256Koblitz, jsonWebKeyStore);
      expect(
          await _verifySdJws(
              sdJws,
              jsonWebKeyStore),
          isTrue);
    });

    test('ECDSA using P-384 and SHA-384', () async {
      JsonWebKeyStore jsonWebKeyStore = JsonWebKeyStore();
      Jws sdJws = _generateSdJws(KeyType.ec, Curve.p384, SigningAlgorithm.ecdsaSha384Prime, jsonWebKeyStore);
      expect(
          await _verifySdJws(
              sdJws,
              jsonWebKeyStore),
          isTrue);
    });

    test('ECDSA using P-384 and SHA-512', () async {
      JsonWebKeyStore jsonWebKeyStore = JsonWebKeyStore();
      try {
        Jws sdJws = _generateSdJws(KeyType.ec, Curve.p384, SigningAlgorithm.ecdsaSha512Prime, jsonWebKeyStore);
        await _verifySdJws(sdJws, jsonWebKeyStore);
      } catch (e){
        print(e);
        expect(e.toString(), 'Exception: Curve cardinality is smaller than digest length, that\'s not possible.');
      }
    });

    test('ECDSA using P-521 and SHA-256', () async {
      JsonWebKeyStore jsonWebKeyStore = JsonWebKeyStore();
      Jws sdJws = _generateSdJws(KeyType.ec, Curve.p521, SigningAlgorithm.ecdsaSha256Prime, jsonWebKeyStore);
      expect(
          await _verifySdJws(
              sdJws,
              jsonWebKeyStore),
          isTrue);
    });

    test('ECDSA using P-521 and SHA-256K', () async {
      JsonWebKeyStore jsonWebKeyStore = JsonWebKeyStore();
      Jws sdJws = _generateSdJws(KeyType.ec, Curve.p521, SigningAlgorithm.ecdsaSha256Koblitz, jsonWebKeyStore);
      expect(
          await _verifySdJws(
              sdJws,
              jsonWebKeyStore),
          isTrue);
    });

    test('ECDSA using P-521 and SHA-384', () async {
      JsonWebKeyStore jsonWebKeyStore = JsonWebKeyStore();
      Jws sdJws = _generateSdJws(KeyType.ec, Curve.p521, SigningAlgorithm.ecdsaSha384Prime, jsonWebKeyStore);
      expect(
          await _verifySdJws(
              sdJws,
              jsonWebKeyStore),
          isTrue);
    });

    test('ECDSA using P-521 and SHA-512', () async {
      JsonWebKeyStore jsonWebKeyStore = JsonWebKeyStore();
      Jws sdJws = _generateSdJws(KeyType.ec, Curve.p521, SigningAlgorithm.ecdsaSha512Prime, jsonWebKeyStore);
      expect(
          await _verifySdJws(
              sdJws,
              jsonWebKeyStore),
          isTrue);
    });
  });
}

Jws _generateSdJws(KeyType keyType, Curve curve, SigningAlgorithm algorithm, JsonWebKeyStore jsonWebKeyStore) {
  Jwk jsonWebKey =
      Jwk(keyType: keyType, key: EcPrivateKey.generate(curve), algorithm: algorithm);
  jsonWebKeyStore.addKey(JsonWebKey.fromJson(jsonWebKey.toJson()));
  var awesome = Jwt(claims: {
    'vc': 'VerifiableCredential'
  });
  Jws sdJws = awesome.sign(jsonWebKey: jsonWebKey);
  print(sdJws.toCompactSerialization());
  print(sdJws.toJson());
  return sdJws;
}

Future<bool> _verifySdJws(Jws sdJws, JsonWebKeyStore jsonWebKeyStore) async {
  JsonWebSignature jsonWebSignature =
      JsonWebSignature.fromCompactSerialization(sdJws.toCompactSerialization().split('~').first);
  return jsonWebSignature.verify(jsonWebKeyStore);
}
