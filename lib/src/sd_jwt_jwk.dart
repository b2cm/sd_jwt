import 'dart:convert';
import 'dart:typed_data';

import 'package:sd_jwt/src/crypto_provider/ed25519_edwards_crypto_provider.dart';
import 'package:sd_jwt/src/crypto_provider/pointycastle_crypto_provider.dart';
import 'package:sd_jwt/src/sd_jwt_crypto_provider.dart';
import 'package:sd_jwt/src/sd_jwt_utils.dart';

enum KeyOperation {
  sign,
  verify,
  encrypt,
  decrypt,
  wrapKey,
  unwrapKey,
  deriveKey,
  deriveBits,
}

enum KeyType {
  ec,
  rsa,
  okt,
  okp,
}

extension KeyTypeNames on KeyType {
  String get name {
    switch (this) {
      case KeyType.ec:
        return 'EC';
      case KeyType.rsa:
        return 'RSA';
      case KeyType.okt:
        return 'oct';
      case KeyType.okp:
        return 'OKP';
    }
  }
}

class Jwk {
  KeyType keyType;
  String? useFor;
  List<KeyOperation>? keyOperations;
  SigningAlgorithm? algorithm;
  String? keyId;
  Uri? x509Url;
  List<String>? x509CertificateChain;
  String? x509CertificateSha1Thumbprint;
  String? x509CertificateSha256Thumbprint;
  Key key;

  Jwk get public {
    return Jwk(keyType: keyType, key: (key as AsymmetricKey).public);
  }

  Jwk(
      {required this.keyType,
      this.useFor,
      this.keyOperations,
      this.algorithm,
      this.keyId,
      this.x509Url,
      this.x509CertificateChain,
      this.x509CertificateSha1Thumbprint,
      this.x509CertificateSha256Thumbprint,
      required this.key});

  Jwk.fromJson(Map<String, dynamic> map)
      : keyType = KeyType.values.first,
        key = EcPrivateKey.generate(Curve.p256) {
    if (map['kty'] is String) {
      if ((map['kty'] as String) == KeyType.okp.name) {
        keyType = KeyType.okp;
        List<String> properties = ['x', 'crv'];
        for (String property in properties) {
          if (!map.containsKey(property)) {
            throw Exception(
                'Key could not be loaded. Property $property not found.');
          }
        }
        Curve curve;
        if (map['crv'] == Curve.curve25519.name) {
          curve = Curve.curve25519;
        } else {
          throw Exception('Curve `${map['crv']} not supported.');
        }
        if (map['d'] == null) {
          key = EdPublicKey(
              pubA: base64.decode(addPaddingToBase64(map['x'])),
              curve: curve);
        } else {
          key = EdPrivateKey(
              pubA: base64.decode(addPaddingToBase64(map['x'])),
              a: base64.decode(addPaddingToBase64(map['d'])),
              curve: curve);
        }
      } else if ((map['kty'] as String) == KeyType.ec.name) {
        keyType = KeyType.ec;
        List<String> properties = ['x', 'y', 'crv'];
        for (String property in properties) {
          if (!map.containsKey(property)) {
            throw Exception(
                'Key could not be loaded. Property $property not found.');
          }
        }
        Curve curve;
        if (map['crv'] == Curve.p256.name) {
          curve = Curve.p256;
        } else if (map['crv'] == Curve.p256k.name) {
          curve = Curve.p256k;
        } else if (map['crv'] == Curve.p384.name) {
          curve = Curve.p384;
        } else if (map['crv'] == Curve.p521.name) {
          curve = Curve.p521;
        } else {
          throw Exception('Curve `${map['crv']} not supported.');
        }
        if (map['d'] == null) {
          key = EcPublicKey(
              x: base64.decode(addPaddingToBase64(map['x'])),
              y: base64.decode(addPaddingToBase64(map['y'])),
              curve: curve);
        } else {
          key = EcPrivateKey(
              x: base64.decode(addPaddingToBase64(map['x'])),
              y: base64.decode(addPaddingToBase64(map['y'])),
              d: base64.decode(addPaddingToBase64(map['d'])),
              curve: curve);
        }
      } else if ((map['kty'] as String) == KeyType.rsa.name) {
        keyType = KeyType.rsa;
        List<String> properties = ['n', 'e', 'd', 'p', 'q', 'dp', 'dq', 'qi'];
        for (String property in properties) {
          if (!map.containsKey(property) || map[property] is! String) {
            throw Exception(
                'Key could not be loaded. Property $property not found.');
          }
        }
        key = RsaPrivateKey(
            n: base64.decode(addPaddingToBase64(map['n'])),
            e: base64.decode(addPaddingToBase64(map['e'])),
            d: base64.decode(addPaddingToBase64(map['d'])),
            p: base64.decode(addPaddingToBase64(map['p'])),
            q: base64.decode(addPaddingToBase64(map['q'])),
            dp: base64.decode(addPaddingToBase64(map['dp'])),
            dq: base64.decode(addPaddingToBase64(map['dq'])),
            qi: base64.decode(addPaddingToBase64(map['qi'])));
      } else {
        throw Exception('Key type `${map['kty']}` not supported.');
      }
    } else {
      throw Exception('Key type property MUST be string.');
    }
    map['use'] != null
        ? map['use'] is String
            ? useFor = map['use']
            : (throw Exception('Use property MUST be string.'))
        : null;
    if (map['key_ops'] != null) {
      if (map['key_ops'] is List) {
        keyOperations = (map['key_ops'] as List).map((e) {
          if (e == KeyOperation.sign.name) {
            return KeyOperation.sign;
          } else if (e == KeyOperation.verify.name) {
            return KeyOperation.verify;
          } else if (e == KeyOperation.encrypt.name) {
            return KeyOperation.encrypt;
          } else if (e == KeyOperation.decrypt.name) {
            return KeyOperation.decrypt;
          } else if (e == KeyOperation.wrapKey.name) {
            return KeyOperation.wrapKey;
          } else if (e == KeyOperation.unwrapKey.name) {
            return KeyOperation.unwrapKey;
          } else if (e == KeyOperation.deriveKey.name) {
            return KeyOperation.deriveKey;
          } else if (e == KeyOperation.deriveBits.name) {
            return KeyOperation.deriveBits;
          } else {
            throw Exception('Key operation `$e` not supported.');
          }
        }).toList();
      } else {
        (throw Exception('Key operations property MUST be list of strings.'));
      }
    }
    if (map['alg'] != null) {
      if (map['alg'] is String) {
        if (map['alg'] == SigningAlgorithm.ecdsaSha256Prime.name) {
          algorithm = SigningAlgorithm.ecdsaSha256Prime;
        } else if (map['alg'] == SigningAlgorithm.ecdsaSha256Koblitz.name) {
          algorithm = SigningAlgorithm.ecdsaSha256Koblitz;
        } else if (map['alg'] == SigningAlgorithm.ecdsaSha384Prime.name) {
          algorithm = SigningAlgorithm.ecdsaSha384Prime;
        } else if (map['alg'] == SigningAlgorithm.ecdsaSha512Prime.name) {
          algorithm = SigningAlgorithm.ecdsaSha512Prime;
        } else if (map['alg'] == SigningAlgorithm.eddsa25519Sha512.name) {
          algorithm = SigningAlgorithm.eddsa25519Sha512;
        } else {
          throw Exception('Algorithm `${map['alg']}` not supported');
        }
      } else {
        throw Exception('Algorithm property MUST be string.');
      }
    }
    map['kid'] != null
        ? map['kid'] is String
            ? keyId = map['kid']
            : (throw Exception('Key identifier property MUST be string.'))
        : null;
    map['x5c'] != null
        ? map['x5c'] is List
            ? x509CertificateChain =
                (map['x5c'] as List).map((e) => e.toString()).toList()
            : (throw Exception(
                'X.509 certificate chain property MUST be a list of strings.'))
        : null;
    map['x5t'] != null
        ? map['x5t'] is String
            ? x509CertificateSha1Thumbprint = map['x5t']
            : (throw Exception(
                'X.509 certificate SHA1 thumbprint property MUST be string.'))
        : null;
    map['x5t#256'] != null
        ? map['x5t#256'] is String
            ? x509CertificateSha256Thumbprint = map['x5t#256']
            : (throw Exception(
                'X.509 certificate SHA256 thumbprint property MUST be string.'))
        : null;
    map['x5u'] != null
        ? map['x5u'] is String
            ? x509Url = Uri.parse(map['x5u'])
            : (throw Exception(
                'X.509 certificate URL property MUST be string.'))
        : null;
  }

  Map<String, dynamic> toJson() {
    Map<String, dynamic> map = {
      'kty': keyType.name,
    };
    useFor != null ? map['use'] = useFor : null;
    keyOperations != null
        ? map['key_ops'] = keyOperations?.map((e) => e.name).toList()
        : null;
    algorithm != null ? map['alg'] = algorithm?.name : null;
    keyId != null ? map['kid'] = keyId : null;
    x509Url != null ? map['x5u'] = x509Url.toString() : null;
    x509CertificateChain != null ? map['x5c'] = x509CertificateChain : null;
    x509CertificateSha1Thumbprint != null
        ? map['x5t'] = x509CertificateSha1Thumbprint
        : null;
    x509CertificateSha256Thumbprint != null
        ? map['x5t#256'] = x509CertificateSha256Thumbprint
        : null;
    if (key is RsaPrivateKey) {
      map['n'] =
          removePaddingFromBase64(base64Url.encode((key as RsaPrivateKey).n));
      map['e'] =
          removePaddingFromBase64(base64Url.encode((key as RsaPrivateKey).e));
      map['d'] =
          removePaddingFromBase64(base64Url.encode((key as RsaPrivateKey).d));
      map['p'] =
          removePaddingFromBase64(base64Url.encode((key as RsaPrivateKey).p));
      map['q'] =
          removePaddingFromBase64(base64Url.encode((key as RsaPrivateKey).q));
      map['dp'] =
          removePaddingFromBase64(base64Url.encode((key as RsaPrivateKey).dp));
      map['dq'] =
          removePaddingFromBase64(base64Url.encode((key as RsaPrivateKey).dq));
      map['qi'] =
          removePaddingFromBase64(base64Url.encode((key as RsaPrivateKey).qi));
    } else if (key is EcPrivateKey) {
      map['x'] =
          removePaddingFromBase64(base64Url.encode((key as EcPrivateKey).x));
      map['y'] =
          removePaddingFromBase64(base64Url.encode((key as EcPrivateKey).y));
      map['d'] =
          removePaddingFromBase64(base64Url.encode((key as EcPrivateKey).d));
      map['crv'] = (key as EcPrivateKey).curve.name;

    } else if (key is EcPublicKey) {
      map['x'] =
          removePaddingFromBase64(base64Url.encode((key as EcPublicKey).x));
      map['y'] =
          removePaddingFromBase64(base64Url.encode((key as EcPublicKey).y));
      map['crv'] = (key as EcPublicKey).curve.name;

    } else if (key is EdPrivateKey) {
      map['d'] = removePaddingFromBase64(base64Url.encode((key as EdPrivateKey).a));
      map['x'] = removePaddingFromBase64(base64Url.encode((key as EdPrivateKey).pubA));
      map['crv'] = (key as EdPublicKey).curve.name;

    } else if (key is EdPublicKey) {
      map['x'] = removePaddingFromBase64(base64Url.encode((key as EdPrivateKey).pubA));
      map['crv'] = (key as EdPublicKey).curve.name;
    }

    return map;
  }

  @override
  String toString() => toJson().toString();
}

abstract class Key {}

abstract class SymmetricKey implements Key {}

abstract class AsymmetricKey implements Key {
  PublicKey get public;
}

abstract class PrivateKey implements AsymmetricKey {
  Uint8List get private;
}

abstract class PublicKey implements AsymmetricKey {}

class RsaPrivateKey implements AsymmetricKey {
  Uint8List n;
  Uint8List e;
  Uint8List d;
  Uint8List p;
  Uint8List q;
  Uint8List dp;
  Uint8List dq;
  Uint8List qi;

  RsaPrivateKey(
      {required this.n,
      required this.e,
      required this.d,
      required this.p,
      required this.q,
      required this.dp,
      required this.dq,
      required this.qi});

  @override
  // TODO: implement public
  PublicKey get public => throw UnimplementedError();
}

abstract class EcKey implements AsymmetricKey {
  Curve curve;

  EcKey({required this.curve});
}

class EcPublicKey extends EcKey implements PublicKey {
  Uint8List x;
  Uint8List y;

  EcPublicKey({required this.x, required this.y, required super.curve});

  @override
  EcPublicKey get public => this;
}

class EcPrivateKey extends EcPublicKey implements PrivateKey {
  Uint8List d;

  EcPrivateKey(
      {required this.d,
      required super.x,
      required super.y,
      required super.curve});

  factory EcPrivateKey.generate(Curve curve) {
    PointyCastleCryptoProvider pointyCastleCryptoProvider =
        PointyCastleCryptoProvider();
    return pointyCastleCryptoProvider.generateKeyPair(keyParameters: EcKeyParameters(curve))
        as EcPrivateKey;
  }

  @override
  EcPublicKey get public => EcPublicKey(x: x, y: y, curve: curve);

  @override
  Uint8List get private => d;
}

class EdPrivateKey extends EdPublicKey implements PrivateKey {
  Uint8List a;

  EdPrivateKey({required super.curve, required this.a, required super.pubA});

  factory EdPrivateKey.generate({required Curve curve, Uint8List? seed}) {
    Ed25519EdwardsCryptoProvider ed25519EdwardsCryptoProvider = Ed25519EdwardsCryptoProvider();
    return ed25519EdwardsCryptoProvider.generateKeyPair(keyParameters: EcKeyParameters(curve), seed: seed) as EdPrivateKey;
  }

  @override
  Uint8List get private => a;
}

class EdPublicKey extends EcKey implements PublicKey {
  Uint8List pubA;

  EdPublicKey({required super.curve, required this.pubA});

  @override
  // TODO: implement public
  PublicKey get public => throw UnimplementedError();
}
