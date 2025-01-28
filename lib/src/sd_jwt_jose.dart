import 'dart:convert';
import 'dart:typed_data';

import 'package:sd_jwt/src/sd_jwt_crypto_provider.dart';
import 'package:sd_jwt/src/sd_jwt_jwk.dart';

class JoseHeader {
  String? type, contentType;
  Uri? jwkSetUri;
  Jwk? jsonWebKey;
  String? keyId;
  Uri? x509certificateUri;
  List<Uint8List>? x509certificateChain;
  Uint8List? x509certificateSha1;
  Uint8List? x509certificateSha256;
  List<String>? critical;
  Map<String, dynamic>? additionalParameters;

  JoseHeader(
      {this.type,
      this.contentType,
      this.jwkSetUri,
      this.jsonWebKey,
      this.keyId,
      this.x509certificateUri,
      this.x509certificateChain,
      this.x509certificateSha1,
      this.x509certificateSha256,
      this.critical,
      this.additionalParameters});

  factory JoseHeader.fromJson(Map<String, dynamic> map) {
    String? type, contentType;
    Uri? jwkSetUri;
    Jwk? jsonWebKey;
    String? keyId;
    Uri? x509certificateUri;
    List<Uint8List>? x509certificateChain;
    Uint8List? x509certificateSha1;
    Uint8List? x509certificateSha256;
    List<String>? critical;
    SigningAlgorithm? alg;
    Map<String, dynamic>? additionalParameters;
    for (MapEntry entry in map.entries) {
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
            (entry.value as List).map((e) => base64.decode(e)).toList();
      } else if (entry.key == 'x5t') {
        x509certificateSha1 = base64Url.decode(entry.value);
      } else if (entry.key == 'x5t#256') {
        x509certificateSha256 = base64Url.decode(entry.value);
      } else if (entry.key == 'crit') {
        critical = entry.value;
      } else if (entry.key == 'typ') {
        type = entry.value;
      } else if (entry.key == 'cty') {
        contentType = entry.value;
      } else if (entry.key == 'alg') {
        alg = map['alg'] != null
            ? SigningAlgorithm.values.singleWhere((e) => e.name == map['alg'])
            : throw Exception('Algorithm ${map['alg']} not supported');
      } else {
        additionalParameters ??= {};
        additionalParameters[entry.key] = entry.value;
      }
    }

    if (additionalParameters != null && additionalParameters.isEmpty) {
      additionalParameters = null;
    }

    if (alg == null) {
      return JoseHeader(
          type: type,
          keyId: keyId,
          additionalParameters: additionalParameters,
          contentType: contentType,
          critical: critical,
          jsonWebKey: jsonWebKey,
          jwkSetUri: jwkSetUri,
          x509certificateChain: x509certificateChain,
          x509certificateSha1: x509certificateSha1,
          x509certificateSha256: x509certificateSha256,
          x509certificateUri: x509certificateUri);
    } else {
      return JwsJoseHeader(
          algorithm: alg,
          type: type,
          keyId: keyId,
          additionalParameters: additionalParameters,
          contentType: contentType,
          critical: critical,
          jsonWebKey: jsonWebKey,
          jwkSetUri: jwkSetUri,
          x509certificateChain: x509certificateChain,
          x509certificateSha1: x509certificateSha1,
          x509certificateSha256: x509certificateSha256,
          x509certificateUri: x509certificateUri);
    }
  }

  Map<String, dynamic> toJson() {
    Map<String, dynamic> map = {};
    type != null ? map['typ'] = type : null;
    contentType != null ? map['cty'] = contentType : null;
    jwkSetUri != null ? map['jku'] = jwkSetUri!.toString() : null;
    jsonWebKey != null ? map['jwk'] = jsonWebKey!.toJson() : null;
    keyId != null ? map['kid'] = keyId! : null;
    x509certificateUri != null
        ? map['x5u'] = x509certificateUri!.toString()
        : null;
    x509certificateChain != null
        ? map['x5c'] =
            x509certificateChain!.map((e) => base64.encode(e)).toList()
        : null;
    x509certificateSha1 != null
        ? map['x5t'] = base64Url.encode(x509certificateSha1!.toList())
        : null;
    x509certificateSha256 != null
        ? map['jku'] = base64Url.encode(x509certificateSha256!.toList())
        : null;
    critical != null ? map['crit'] = critical : null;
    if (additionalParameters != null) map.addAll(additionalParameters!);
    return map;
  }

  @override
  String toString() => toJson().toString();
}

class JwsJoseHeader extends JoseHeader {
  SigningAlgorithm algorithm;

  JwsJoseHeader(
      {required this.algorithm,
      super.type,
      super.contentType,
      super.jwkSetUri,
      super.jsonWebKey,
      super.keyId,
      super.x509certificateUri,
      super.x509certificateChain,
      super.x509certificateSha1,
      super.x509certificateSha256,
      super.critical,
      super.additionalParameters});

  @override
  Map<String, dynamic> toJson() {
    Map<String, dynamic> map = {'alg': algorithm.name};
    map.addAll(super.toJson());
    return map;
  }
}

class JweJoseHeader extends JoseHeader {}
