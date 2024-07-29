import 'dart:convert';
import 'dart:typed_data';

import 'package:sd_jwt/src/sd_jwt_crypto_provider.dart';
import 'package:sd_jwt/src/sd_jwt_jwk.dart';

class JoseHeader {
  String? type;
  String? contentType;
  Map<String, dynamic> additionalUnprotected;

  JoseHeader(
      {this.type,
      this.contentType,
      Map<String, dynamic>? additionalUnprotected})
      : additionalUnprotected = additionalUnprotected ?? <String, dynamic>{};

  factory JoseHeader.fromJson(Map<String, dynamic> map) {
    if (map['protected'] != null) {
      return JwsJoseHeader.fromJson(map);
    } else {
      return JoseHeader.fromJson(map);
    }
  }

  Map<String, dynamic> toJson() {
    Map<String, dynamic> map = {...additionalUnprotected};
    type != null ? map['typ'] = type : null;
    contentType != null ? map['cty'] = contentType : null;
    return map;
  }

  @override
  String toString() => toJson().toString();
}

class JwsJoseHeader extends JoseHeader {
  SigningAlgorithm algorithm;
  Uri? jwkSetUri;
  Jwk? jsonWebKey;
  String? keyId;
  Uri? x509certificateUri;
  List<Uint8List>? x509certificateChain;
  Uint8List? x509certificateSha1;
  Uint8List? x509certificateSha256;
  List<String>? critical;
  Map<String, dynamic> additionalProtected;

  JwsJoseHeader(
      {required this.algorithm,
      super.type,
      super.contentType,
      this.jwkSetUri,
      this.jsonWebKey,
      this.keyId,
      this.x509certificateUri,
      this.x509certificateChain,
      this.x509certificateSha1,
      this.x509certificateSha256,
      this.critical,
      Map<String, dynamic>? additionalProtected,
      Map<String, dynamic>? additionalUnprotected})
      : additionalProtected = additionalProtected ?? <String, dynamic>{} {
    super.additionalUnprotected = additionalUnprotected ?? <String, dynamic>{};
  }

  JwsJoseHeader.fromJson(Map<String, dynamic> map)
      : algorithm = map['protected']['alg'] != null
            ? SigningAlgorithm.values
                .singleWhere((e) => e.name == map['protected']['alg'])
            : throw Exception(),
        additionalProtected = {} {
    Map<String, dynamic> protected = map['protected'] ??= <String, dynamic>{};
    Map<String, dynamic> unprotected =
        map['unprotected'] ??= <String, dynamic>{};

    for (MapEntry entry in protected.entries) {
      if (entry.key == 'jku') {
        jwkSetUri = Uri.tryParse(entry.value);
      } else if (entry.key == 'jwk') {
        jsonWebKey = Jwk.fromJson(entry.value);
      } else if (entry.key == 'kid') {
        keyId = entry.value;
      } else if (entry.key == 'x5u') {
        x509certificateUri = Uri.tryParse(entry.value);
      } else if (entry.key == 'x5c') {
        x509certificateChain =
            (entry.value as List<String>).map((e) => base64.decode(e)).toList();
      } else if (entry.key == 'x5t') {
        x509certificateSha1 = base64Url.decode(entry.value);
      } else if (entry.key == 'x5t#256') {
        x509certificateSha256 = base64Url.decode(entry.value);
      } else if (entry.key == 'crit') {
        critical = entry.value;
      } else {
        additionalProtected[entry.key] = entry.value;
      }
    }

    for (MapEntry entry in unprotected.entries) {
      if (entry.key == 'typ') {
        super.type = entry.value;
      } else if (entry.key == 'cty') {
        super.contentType = entry.value;
      } else {
        additionalUnprotected[entry.key] = entry.value;
      }
    }
  }

  @override
  Map<String, dynamic> toJson() => {
        'protected': protected,
        'unprotected': unprotected,
      };

  Map<String, dynamic> get protected {
    Map<String, dynamic> map = {...additionalProtected, 'alg': algorithm.name};
    jwkSetUri != null ? map['jku'] = jwkSetUri!.toString() : null;
    jsonWebKey != null ? map['jwk'] = jsonWebKey!.toJson() : null;
    keyId != null ? map['kid'] = keyId! : null;
    x509certificateUri != null
        ? map['x5u'] = x509certificateUri!.toString()
        : null;
    x509certificateChain != null
        ? map['x5c'] = x509certificateChain!.map((e) => base64.encode(e))
        : null;
    x509certificateSha1 != null
        ? map['x5t'] = base64Url.encode(x509certificateSha1!.toList())
        : null;
    x509certificateSha256 != null
        ? map['jku'] = base64Url.encode(x509certificateSha256!.toList())
        : null;
    critical != null ? map['crit'] = critical : null;
    return map;
  }

  Map<String, dynamic> get unprotected => super.toJson();
}

class JweJoseHeader extends JoseHeader {}
