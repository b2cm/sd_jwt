import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:sd_jwt/src/crypto_provider/pointycastle_crypto_provider.dart';
import 'package:sd_jwt/src/sd_jwt_crypto_provider.dart';
import 'package:sd_jwt/src/sd_jwt_jose.dart';
import 'package:sd_jwt/src/sd_jwt_jwk.dart';
import 'package:sd_jwt/src/sd_jwt_jws.dart';
import 'package:sd_jwt/src/sd_jwt_rfc.dart';
import 'package:sd_jwt/src/sd_jwt_utils.dart';
import 'package:uuid/data.dart';
import 'package:uuid/rng.dart';
import 'package:uuid/uuid.dart';

class SdJwt extends Jwt {
  Map<String, dynamic> _disclosures = {};
  SaltAlgorithm? _saltAlgorithm;
  final DigestAlgorithm _digestAlgorithm;
  Map<String, dynamic> _alwaysDisclosed = {};
  DecoyFactor decoyFactor;
  int _decoyMaxCount = 0;

  set alwaysDisclosed(Map<String, dynamic> value) {
    _alwaysDisclosed = value;
  }

  Map<String, dynamic> get disclosures =>
      _mergePayloadMap(_disclosures, _alwaysDisclosed);

  @override
  Map<String, dynamic> get payload {
    Map<String, dynamic> map = _decoyDigestsMap(_undisclosePayloadMap(
        _mergePayloadMap(_disclosures, _alwaysDisclosed)));
    issuer != null ? map['iss'] = issuer : null;
    subject != null ? map['sub'] = subject : null;
    audience != null ? map['aud'] = audience : null;
    expirationTime != null
        ? map['exp'] = (expirationTime!.millisecondsSinceEpoch / 1000).ceil()
        : null;
    notBefore != null
        ? map['nbf'] = (notBefore!.millisecondsSinceEpoch / 1000).ceil()
        : null;
    issuedAt != null
        ? map['iat'] = (issuedAt!.millisecondsSinceEpoch / 1000).ceil()
        : null;
    jwtId != null ? map['jti'] = jwtId : null;
    map['_sd_alg'] = _digestAlgorithm.name;
    confirmation != null ? map['cnf'] = confirmation!.toJson() : null;
    return map;
  }

  SdJwt({
    required super.claims,
    Map<String, dynamic>? alwaysDisclosed,
    SaltAlgorithm saltAlgorithm = SaltAlgorithm.randomBase64UrlNoPadding256,
    DigestAlgorithm digestAlgorithm = DigestAlgorithm.sha256,
    super.issuer,
    super.subject,
    super.audience,
    super.expirationTime,
    super.notBefore,
    super.issuedAt,
    super.jwtId,
    super.header,
    this.decoyFactor = DecoyFactor.none,
  })  : _saltAlgorithm = saltAlgorithm,
        _digestAlgorithm = digestAlgorithm {
    _parseRegisteredClaims();
    _removeRegisteredClaims();
    _disclosures =
        _createDisclosuresMap(super.claims, saltAlgorithm, digestAlgorithm);
    alwaysDisclosed != null ? _alwaysDisclosed = alwaysDisclosed : null;
  }

  SdJwt.verified(SdJws sdJws, Jwk jsonWebKey)
      : _digestAlgorithm = DigestAlgorithm.values
            .singleWhere((e) => e.name == sdJws.payload['_sd_alg']),
        decoyFactor = DecoyFactor.none,
        super.verified(sdJws, jsonWebKey) {
    claims.remove('_sd_alg');

    if (sdJws.disclosures != null) {
      _disclosures = _deepCopyMap(claims);
      _disclosures = _restoreDisclosuresMap(_disclosures, sdJws.disclosures!);
      claims = _deepCopyMap(_disclosures);
      claims = _restoreClaimsMap(claims);
    }
  }

  SdJwt.fromJson(Map<String, dynamic> map)
      : _digestAlgorithm = DigestAlgorithm.values
            .singleWhere((e) => e.name == map['payload']['_sd_alg']),
        decoyFactor = DecoyFactor.none,
        super.fromJson(map) {
    if (map['disclosures'] != null) {
      List<Disclosure> disclosuresList = (map['disclosures'] as List)
          .map((e) => e is Map<String, dynamic>
              ? Disclosure.fromJson(e)
              : throw Exception('${e.runtimeType} not supported.'))
          .toList();
      _disclosures = _deepCopyMap(claims);
      _disclosures = _restoreDisclosuresMap(_disclosures, disclosuresList);
      claims = _deepCopyMap(_disclosures);
      claims = _restoreClaimsMap(claims);
    }
  }

  void build({SaltAlgorithm? saltAlgorithm}) {
    if (saltAlgorithm == null && _saltAlgorithm == null) {
      throw Exception('Cannot build disclosures, no salt algorithm set.');
    }
    _disclosures = _createDisclosuresMap(
        super.payload, saltAlgorithm ?? _saltAlgorithm!, _digestAlgorithm);
  }

  @override
  SdJws sign(
      {required Jwk jsonWebKey,
      JwsJoseHeader? header,
      SigningAlgorithm? signingAlgorithm}) {
    List<Disclosure> disclosuresList = [];
    _getDisclosuresMap(_disclosures, disclosuresList);
    Jws jws =
        super.sign(jsonWebKey: jsonWebKey, signingAlgorithm: signingAlgorithm);
    return SdJws(
      payload: jws.payload,
      signature: jws.signature,
      header: jws.header,
      disclosures: disclosuresList,
      digestAlgorithm: _digestAlgorithm,
    );
  }

  @override
  Map<String, dynamic> toJson() {
    Map<String, dynamic> map = super.toJson();
    List<Disclosure> disclosuresList = [];
    _getDisclosuresMap(disclosures, disclosuresList);
    map['disclosures'] = disclosuresList.map((e) => e.toJson()).toList();
    return map;
  }

  Map<String, dynamic> _deepCopyMap(Map<String, dynamic> original) {
    Map<String, dynamic> copy = {};

    original.forEach((key, value) {
      if (value is Map<String, dynamic>) {
        copy[key] = _deepCopyMap(value);
      } else if (value is List) {
        copy[key] = List.from(value.map((item) =>
            item is Map<String, dynamic> ? _deepCopyMap(item) : item));
      } else {
        copy[key] = value;
      }
    });

    return copy;
  }

  _decoyDigestsMap(Map<String, dynamic> map) {
    for (MapEntry entry in map.entries) {
      if (entry.key == '_sd' && decoyFactor.value > 0) {
        final Random random = Random.secure();
        List<String> digests = entry.value as List<String>;
        int numberOfDecoys =
            (_decoyMaxCount * decoyFactor.value - digests.length).round();
        for (var i = 0; i < numberOfDecoys; i++) {
          digests.add(removePaddingFromBase64(base64Url.encode(
              Uint8List.fromList(
                  List.generate(32, (_) => random.nextInt(256))))));
        }
      } else if (entry.value is Map) {
        map[entry.key] = _decoyDigestsMap(entry.value);
      } else if (entry.value is List) {
        map[entry.key] = _decoyDigestsList(entry.value);
      }
    }
    return map;
  }

  _decoyDigestsList(List<dynamic> list) {
    int disclosuresCount = 0;
    for (dynamic entry in list) {
      if (entry is Map<String, dynamic>) {
        if (entry.containsKey('...')) {
          disclosuresCount++;
        } else {
          entry = _decoyDigestsMap(entry);
        }
      } else if (entry is List) {
        entry = _decoyDigestsList(entry);
      }
    }

    if (disclosuresCount > 0) {
      final Random random = Random.secure();
      int numberOfDecoys =
          (_decoyMaxCount * decoyFactor.value - disclosuresCount).round();
      for (var i = 0; i < numberOfDecoys; i++) {
        list.add({
          '...': removePaddingFromBase64(base64Url.encode(Uint8List.fromList(
              List.generate(32, (_) => random.nextInt(256)))))
        });
      }
    }
    return list;
  }

  _restoreClaimsMap(Map<String, dynamic> map) {
    for (MapEntry entry in map.entries) {
      if (entry.value is Map) {
        map[entry.key] = _restoreClaimsMap(entry.value);
      } else if (entry.value is List) {
        map[entry.key] = _restoreClaimsList(entry.value);
      } else if (entry.value is Disclosure) {
        map[entry.key] = (entry.value as Disclosure).value;
      } else if (entry.value is String) {
        continue;
      } else if (entry.value is num) {
        continue;
      } else {
        throw Exception();
      }
    }
    return map;
  }

  _restoreClaimsList(List<dynamic> list) {
    for (dynamic entry in list) {
      if (entry is Map<String, dynamic>) {
        list[list.indexOf(entry)] = _restoreClaimsMap(entry);
      } else if (entry is List) {
        list[list.indexOf(entry)] = _restoreClaimsList(entry);
      } else if (entry is Disclosure) {
        list[list.indexOf(entry)] = entry.value;
      } else if (entry is String) {
        continue;
      } else if (entry is num) {
        continue;
      } else {
        throw Exception();
      }
    }
    return list;
  }

  _restoreDisclosuresMap(
      Map<String, dynamic> map, List<Disclosure> disclosures) {
    Map<String, dynamic> tmp = {};

    for (MapEntry entry in map.entries) {
      if (entry.key == '_sd') {
        for (Disclosure disclosure in disclosures) {
          if ((entry.value as List).contains(removePaddingFromBase64(
              base64Url.encode(disclosure.digest(_digestAlgorithm))))) {
            tmp[disclosure.key!] = disclosure;
          }
        }
      } else if (entry.value is Map) {
        map[entry.key] = _restoreDisclosuresMap(entry.value, disclosures);
      } else if (entry.value is List) {
        map[entry.key] = _restoreDisclosuresList(entry.value, disclosures);
      } else if (entry.value is String) {
        continue;
      } else if (entry.value is num) {
        continue;
      } else {
        throw Exception();
      }
    }
    map.addAll(tmp);
    map.remove('_sd');
    return map;
  }

  _restoreDisclosuresList(List<dynamic> list, List<Disclosure> disclosures) {
    List removals = [];
    for (dynamic entry in list) {
      if (entry is Map<String, dynamic>) {
        if (entry.containsKey('...')) {
          bool found = false;

          for (Disclosure disclosure in disclosures) {
            if (entry['...'] ==
                removePaddingFromBase64(
                    base64Url.encode(disclosure.digest(_digestAlgorithm)))) {
              list[list.indexOf(entry)] = disclosure;
              found = true;
            }
          }

          if (!found) {
            removals.add(entry);
          }
        } else {
          list[list.indexOf(entry)] =
              _restoreDisclosuresMap(entry, disclosures);
        }
      } else if (entry is List) {
        list[list.indexOf(entry)] = _restoreDisclosuresList(entry, disclosures);
      } else if (entry is String) {
        continue;
      } else if (entry is num) {
        continue;
      } else {
        throw Exception();
      }
    }

    for (dynamic entry in removals) {
      list.remove(entry);
    }

    return list;
  }

  // void changeDisclosure(Disclosure origin, Disclosure changed) {
  // Iterable<Disclosure> disclosure = _disclosures.where((element) =>
  //     element.salt == origin.salt &&
  //     element.key == origin.key &&
  //     element.value == origin.value);
  // if (disclosure.length > 1) {
  //   throw Exception('This should not be happen.');
  // }
  // String originDigest =
  //     removePaddingFromBase64(base64Url.encode(disclosure.first.digest));
  // _changeDisclosureMap(payload, origin, changed);
  // }

  Map<String, dynamic> _undisclosePayloadMap(Map<String, dynamic> map) {
    map = Map<String, dynamic>.of(map);
    List<String> digests = [];
    List<String> deletions = [];
    int decoyCount = 0;

    for (MapEntry entry in map.entries) {
      if (entry.value is Map) {
        map[entry.key] = _undisclosePayloadMap(entry.value);
      } else if (entry.value is List) {
        map[entry.key] = _undisclosePayloadList(entry.value);
      } else if (entry.value is String) {
        continue;
      } else if (entry.value is Disclosure) {
        digests.add(removePaddingFromBase64(base64Url
            .encode((entry.value as Disclosure).digest(_digestAlgorithm))));
        deletions.add(entry.key);
        decoyCount++;
      } else if (entry.value is num) {
        continue;
      } else {
        throw Exception();
      }
    }

    if (decoyCount > _decoyMaxCount) {
      _decoyMaxCount = decoyCount;
    }

    if (digests.isNotEmpty) {
      map['_sd'] = digests;
    }

    for (String key in deletions) {
      map.remove(key);
    }

    return map;
  }

  List<dynamic> _undisclosePayloadList(List<dynamic> list) {
    list = List<dynamic>.of(list);
    int decoyCount = 0;

    for (dynamic entry in list) {
      if (entry is Map<String, dynamic>) {
        list[list.indexOf(entry)] = _undisclosePayloadMap(entry);
      } else if (entry is List) {
        list[list.indexOf(entry)] = _undisclosePayloadList(entry);
      } else if (entry is String) {
        continue;
      } else if (entry is Disclosure) {
        list[list.indexOf(entry)] = {
          '...': removePaddingFromBase64(
              base64Url.encode((entry).digest(_digestAlgorithm)))
        };
        decoyCount++;
      } else if (entry is num) {
        continue;
      } else {
        throw Exception();
      }
    }

    if (decoyCount > _decoyMaxCount) {
      _decoyMaxCount = decoyCount;
    }

    return list;
  }

  Map<String, dynamic> _createDisclosuresMap(Map<String, dynamic> map,
      SaltAlgorithm saltAlgorithm, DigestAlgorithm digestAlgorithm) {
    map = Map<String, dynamic>.of(map);

    for (MapEntry entry in map.entries) {
      if (Jwt._registeredClaimNames.contains(entry.key)) {
        continue;
      }
      if (entry.value is Map) {
        map[entry.key] =
            _createDisclosuresMap(entry.value, saltAlgorithm, digestAlgorithm);
      } else if (entry.value is List) {
        map[entry.key] =
            _createDisclosuresList(entry.value, saltAlgorithm, digestAlgorithm);
      } else if (entry.value is String || entry.value is num) {
        Disclosure disclosure = Disclosure(
            saltAlgorithm: saltAlgorithm,
            key: entry.key,
            value: entry.value,
            digestAlgorithm: digestAlgorithm);
        map[entry.key] = disclosure;
      } else if (entry.value is Disclosure) {
        continue;
      } else {
        throw Exception();
      }
    }
    return map;
  }

  List<dynamic> _createDisclosuresList(List<dynamic> list,
      SaltAlgorithm saltAlgorithm, DigestAlgorithm digestAlgorithm) {
    list = List<dynamic>.of(list);
    for (dynamic entry in list) {
      if (entry is Map<String, dynamic>) {
        list[list.indexOf(entry)] =
            _createDisclosuresMap(entry, saltAlgorithm, digestAlgorithm);
      } else if (entry is List) {
        list[list.indexOf(entry)] =
            _createDisclosuresList(entry, saltAlgorithm, digestAlgorithm);
      } else if (entry is String || entry is num) {
        Disclosure disclosure = Disclosure(
            saltAlgorithm: saltAlgorithm,
            value: entry,
            digestAlgorithm: digestAlgorithm);
        list[list.indexOf(entry)] = disclosure;
      } else {
        throw Exception();
      }
    }
    return list;
  }

  Map<String, dynamic> _getDisclosuresMap(
      Map<String, dynamic> map, List<Disclosure> disclosures) {
    map = Map<String, dynamic>.of(map);

    for (MapEntry entry in map.entries) {
      if (Jwt._registeredClaimNames.contains(entry.key)) {
        continue;
      }
      if (entry.value is Map) {
        map[entry.key] = _getDisclosuresMap(entry.value, disclosures);
      } else if (entry.value is List) {
        map[entry.key] = _getDisclosuresList(entry.value, disclosures);
      } else if (entry.value is String) {
        continue;
      } else if (entry.value is Disclosure) {
        disclosures.add((entry.value));
      } else if (entry.value is num) {
        continue;
      } else {
        throw Exception();
      }
    }
    return map;
  }

  List<dynamic> _getDisclosuresList(
      List<dynamic> list, List<Disclosure> disclosures) {
    list = List<dynamic>.of(list);
    for (dynamic entry in list) {
      if (entry is Map<String, dynamic>) {
        list[list.indexOf(entry)] = _getDisclosuresMap(entry, disclosures);
      } else if (entry is List) {
        list[list.indexOf(entry)] = _getDisclosuresList(entry, disclosures);
      } else if (entry is String) {
        continue;
      } else if (entry is Disclosure) {
        disclosures.add(entry);
      } else if (entry is num) {
        continue;
      } else {
        throw Exception();
      }
    }
    return list;
  }

  Map<String, dynamic> _mergePayloadMap(
      Map<String, dynamic> left, Map<String, dynamic> right) {
    Map<String, dynamic> map = Map.of(left);

    for (MapEntry entry in right.entries) {
      if (entry.value is Map) {
        if (left.containsKey(entry.key) && left[entry.key] is Map) {
          map[entry.key] = _mergePayloadMap(left[entry.key], entry.value);
        }
      } else if (entry.value is List) {
        if (left.containsKey(entry.key) && left[entry.key] is List) {
          map[entry.key] = _mergePayloadList(left[entry.key], entry.value);
        }
      } else {
        if (left.containsKey(entry.key)) {
          continue;
        } else {
          map[entry.key] = entry.value;
        }
      }
    }
    return map;
  }

  List<dynamic> _mergePayloadList(List<dynamic> left, List<dynamic> right) {
    List<dynamic> list = List.of(left);
    for (dynamic entry in right) {
      if (entry is Map<String, dynamic>) {
        if (left.contains(entry) &&
            left.elementAt(left.indexOf(entry)) is Map) {
          list[list.indexOf(entry)] =
              _mergePayloadMap(left.elementAt(left.indexOf(entry)), entry);
        }
      } else if (entry is List) {
        if (left.contains(entry) &&
            left.elementAt(left.indexOf(entry)) is List) {
          list[list.indexOf(entry)] =
              _mergePayloadList(left.elementAt(left.indexOf(entry)), entry);
        }
      } else {
        if (left.contains(entry)) {
          continue;
        } else {
          list.add(entry);
        }
      }
    }
    return list;
  }
}

class Jwt {
  Map<String, dynamic> claims;
  String? issuer;
  String? subject;
  String? audience;
  DateTime? expirationTime;
  DateTime? notBefore;
  DateTime? issuedAt;
  String? jwtId;
  Confirmation? confirmation;
  bool _isVerified = false;
  final JoseHeader _header;
  static final List<String> _registeredClaimNames = [
    'iss',
    'sub',
    'aud',
    'exp',
    'nbf',
    'iat',
    'jti'
  ];

  bool get isVerified => _isVerified;

  JoseHeader get header => _header;

  Map<String, dynamic> get payload {
    Map<String, dynamic> map = Map<String, dynamic>.of(claims);
    issuer != null ? map['iss'] = issuer : null;
    subject != null ? map['sub'] = subject : null;
    audience != null ? map['aud'] = audience : null;
    expirationTime != null
        ? map['exp'] = (expirationTime!.millisecondsSinceEpoch / 1000).ceil()
        : null;
    notBefore != null
        ? map['nbf'] = (notBefore!.millisecondsSinceEpoch / 1000).ceil()
        : null;
    issuedAt != null
        ? map['iat'] = (issuedAt!.millisecondsSinceEpoch / 1000).ceil()
        : null;
    jwtId != null ? map['jti'] = jwtId : null;
    confirmation != null ? map['cnf'] = confirmation!.toJson() : null;
    return map;
  }

  Jwt(
      {required this.claims,
      this.issuer,
      this.subject,
      this.audience,
      this.expirationTime,
      this.notBefore,
      this.issuedAt,
      this.jwtId,
      JoseHeader? header})
      : _header = header ??= JoseHeader() {
    _parseRegisteredClaims();
    _removeRegisteredClaims();
  }

  Jwt.fromJson(Map<String, dynamic> map)
      : claims = map['payload'],
        _header = JoseHeader.fromJson(map['header']) {
    _parseRegisteredClaims();
    _removeRegisteredClaims();
  }

  Jwt.verified(Jws jsonWebSignature, Jwk jsonWebKey)
      : claims = Map.of(jsonWebSignature.payload),
        _header = jsonWebSignature.header {
    Uint8List signature = jsonWebSignature.signature;
    Uint8List signingInput = RFC7515.signingInput(
        payload: jsonWebSignature.payload,
        protectedHeader: jsonWebSignature.header.protected);

    if (jsonWebKey.keyType == KeyType.ec) {
      PointyCastleCryptoProvider pointyCastleCryptoProvider =
          PointyCastleCryptoProvider();

      if (jsonWebSignature.header.algorithm.digestLength >
          (jsonWebKey.key as EcPublicKey).crv.length) {
        throw Exception(
            'Curve cardinality is smaller than digest length, that\'s not possible.');
      }
      EcSignature ecSignature = EcSignature(
          Uint8List.fromList(signature.getRange(0, 32).toList()),
          Uint8List.fromList(signature.getRange(32, 64).toList()));

      if (pointyCastleCryptoProvider.verify(
          data: signingInput,
          publicKey: jsonWebKey.key as EcPublicKey,
          algorithm: jsonWebSignature.header.algorithm,
          signature: ecSignature)) {
        _isVerified = true;
        _parseRegisteredClaims();
        _removeRegisteredClaims();
      } else {
        throw Exception('Verification failed.');
      }
    }
  }

  Jws sign(
      {required Jwk jsonWebKey,
      JwsJoseHeader? header,
      SigningAlgorithm? signingAlgorithm}) {
    if (jsonWebKey.algorithm == null && signingAlgorithm == null) {
      throw Exception('Signing algorithm not set!');
    }

    signingAlgorithm ??= jsonWebKey.algorithm!;

    JwsJoseHeader jwsHeader;
    if (header != null) {
      jwsHeader = header;
    } else if (_header is JwsJoseHeader) {
      jwsHeader = _header;
    } else {
      jwsHeader = JwsJoseHeader(
          algorithm: signingAlgorithm,
          type: _header.type,
          contentType: _header.contentType,
          additionalUnprotected: _header.additionalUnprotected,
          additionalProtected: null);
    }

    Map<String, dynamic> signedPayload = Map.of(payload);

    Uint8List signingInput = RFC7515.signingInput(
        protectedHeader: jwsHeader.protected, payload: signedPayload);

    if (jsonWebKey.keyType == KeyType.ec) {
      PointyCastleCryptoProvider pointyCastleCryptoProvider =
          PointyCastleCryptoProvider();
      if (signingAlgorithm.digestLength >
          (jsonWebKey.key as EcPrivateKey).crv.length) {
        throw Exception(
            'Curve cardinality is smaller than digest length, that\'s not possible.');
      }
      if (jsonWebKey.key is! EcPrivateKey) {
        throw Exception('JSON Web Key contains no private key.');
      }

      Uint8List signature = pointyCastleCryptoProvider.sign(
          data: signingInput,
          privateKey: jsonWebKey.key as EcPrivateKey,
          algorithm: signingAlgorithm);

      return Jws(
        payload: signedPayload,
        signature: signature,
        header: jwsHeader,
      );
    } else {
      throw Exception();
    }
  }

  Map<String, dynamic> toJson() =>
      {'header': _header.toJson(), 'payload': payload};

  String toJsonString() => json.encode(toJson());

  @override
  String toString() => toJson().toString();

  void _parseRegisteredClaims() {
    if (subject == null && claims['sub'] != null) {
      subject = claims['sub'];
    }
    if (issuer == null && claims['iss'] != null) {
      issuer = claims['iss'];
    }
    if (audience == null && claims['aud'] != null) {
      audience = claims['aud'];
    }
    if (expirationTime == null && claims['exp'] != null) {
      expirationTime = claims['exp'];
    }
    if (notBefore == null && claims['nbf'] != null) {
      notBefore = claims['nbf'];
    }
    if (issuedAt == null && claims['iat'] != null) {
      try {
        issuedAt = DateTime.fromMillisecondsSinceEpoch(claims['iat'] * 1000);
      } on Exception {
        rethrow;
      }
    }
    if (jwtId == null && claims['jti'] != null) {
      jwtId = claims['jti'];
    }
    if (confirmation == null && claims['cnf'] != null) {
      if (claims['cnf'] is Map && (claims['cnf'] as Map).containsKey('jwk')) {
        confirmation = JwkConfirmation.fromJson(claims['cnf']);
      }
    }
  }

  void _removeRegisteredClaims() {
    claims.remove('sub');
    claims.remove('iss');
    claims.remove('aud');
    claims.remove('exp');
    claims.remove('nbf');
    claims.remove('iat');
    claims.remove('jti');
    claims.remove('cnf');
  }
}

class Disclosure {
  String salt;
  String? key;
  dynamic value;

  Uint8List get bytes {
    List digestInputList;
    key != null
        ? digestInputList = [salt, key, value]
        : digestInputList = [salt, value];
    Uint8List digestInput =
        utf8.encode(json.encode(digestInputList).replaceAll(',', ', '));
    return digestInput;
  }

  Uint8List digest(DigestAlgorithm digestAlgorithm) {
    List digestInputList;
    key != null
        ? digestInputList = [salt, key, value]
        : digestInputList = [salt, value];
    Uint8List digestInput = ascii.encode(base64Url.encode(
        utf8.encode(json.encode(digestInputList).replaceAll(',', ', '))));
    PointyCastleCryptoProvider pointyCastleCryptoProvider =
        PointyCastleCryptoProvider();
    return pointyCastleCryptoProvider.digest(
        data: digestInput, algorithm: digestAlgorithm);
  }

  Disclosure(
      {this.key,
      this.value,
      String? salt,
      SaltAlgorithm? saltAlgorithm,
      DigestAlgorithm digestAlgorithm = DigestAlgorithm.sha256})
      : salt = salt ??= SaltValue(
                saltAlgorithm ?? SaltAlgorithm.randomBase64UrlNoPadding256)
            .value;

  Disclosure.fromJson(Map<String, dynamic> map)
      : salt = map['salt'],
        key = map['key'],
        value = map['value'];

  Map<String, dynamic> toJson() {
    Map<String, dynamic> map = {
      'value': value,
      'salt': salt,
    };
    key != null ? map['key'] = key : null;
    return map;
  }

  @override
  String toString() => toJson().toString();
}

abstract class Confirmation {
  Map<String, dynamic> toJson();
}

class JwkConfirmation implements Confirmation {
  Jwk jwk;

  JwkConfirmation(this.jwk);

  JwkConfirmation.fromJson(Map<String, dynamic> map)
      : jwk = Jwk.fromJson(map['jwk']);

  @override
  Map<String, dynamic> toJson() => {
        'jwk': jwk.toJson(),
      };

  @override
  String toString() => toJson().toString();
}

enum DecoyFactor {
  none,
  tenth,
  fifth,
  quarter,
  third,
  half,
  single,
  double,
  triple,
  quadruple,
  quintuple,
  tenfold,
}

extension DecoyFactorValues on DecoyFactor {
  double get value {
    switch (this) {
      case DecoyFactor.none:
        return 0;
      case DecoyFactor.tenth:
        return 0.1;
      case DecoyFactor.fifth:
        return 0.20;
      case DecoyFactor.quarter:
        return 0.25;
      case DecoyFactor.third:
        return 0.33;
      case DecoyFactor.half:
        return 0.5;
      case DecoyFactor.single:
        return 1;
      case DecoyFactor.double:
        return 2;
      case DecoyFactor.triple:
        return 3;
      case DecoyFactor.quadruple:
        return 4;
      case DecoyFactor.quintuple:
        return 5;
      case DecoyFactor.tenfold:
        return 10;
    }
  }
}

enum SaltAlgorithm {
  uuidV4,
  randomBase64UrlNoPadding128,
  randomBase64UrlNoPadding256,
  randomBase64UrlNoPadding512,
}

class SaltValue {
  final String _value;

  String get value => _value;

  SaltValue(SaltAlgorithm saltAlgorithm) : _value = generate(saltAlgorithm);

  static String generate(SaltAlgorithm saltAlgorithm) {
    switch (saltAlgorithm) {
      case SaltAlgorithm.randomBase64UrlNoPadding128:
        return RandomBase64SaltValue(padding: false, urlSafe: true, length: 128)
            .value;
      case SaltAlgorithm.randomBase64UrlNoPadding256:
        return RandomBase64SaltValue(padding: false, urlSafe: true, length: 256)
            .value;
      case SaltAlgorithm.randomBase64UrlNoPadding512:
        return RandomBase64SaltValue(padding: false, urlSafe: true, length: 512)
            .value;
      case SaltAlgorithm.uuidV4:
        // Only v4 is based on pseudo random generator!
        return UuidSaltValue(version: UuidVersion.v4).value;
    }
  }
}

class UuidSaltValue implements SaltValue {
  @override
  final String _value;

  @override
  String get value => _value;

  UuidSaltValue({UuidVersion version = UuidVersion.v4})
      : _value = generate(version);

  static String generate(UuidVersion version) {
    switch (version) {
      case UuidVersion.v4:
        return Uuid().v4(config: V4Options(null, CryptoRNG()));
    }
  }
}

class RandomBase64SaltValue implements SaltValue {
  @override
  final String _value;
  int length;

  @override
  String get value => _value;

  RandomBase64SaltValue(
      {bool padding = false, bool urlSafe = true, this.length = 256})
      : _value = generate(length: length);

  static String generate(
      {bool padding = false, bool urlSafe = true, required int length}) {
    if (length % 8 != 0) {
      throw Exception('Length of random bits must be dividable by 8.');
    }
    List<int> randomBytes =
        List<int>.generate(length ~/ 8, (i) => Random.secure().nextInt(256));
    String salt;
    if (urlSafe) {
      salt = base64Url.encode(randomBytes);
    } else {
      salt = base64.encode(randomBytes);
    }
    if (!padding) {
      salt = removePaddingFromBase64(salt);
    }
    return salt;
  }
}

enum UuidVersion {
  v4,
}

class KbJwt extends Jwt {
  String nonce;
  Uint8List sdHash;

  @override
  Map<String, dynamic> get payload {
    return super.payload
      ..addAll({
        'nonce': nonce,
        'sd_hash': base64Url.encode(sdHash),
      });
  }

  KbJwt(
      {required super.audience,
      required super.issuedAt,
      required this.nonce,
      required this.sdHash})
      : super(claims: {}) {
    issuedAt ??= DateTime.now();
  }

  KbJwt.verified(super.jsonWebSignature, super.jsonWebKey)
      : sdHash = base64Url.decode(jsonWebSignature.payload['sd_hash']),
        nonce = jsonWebSignature.payload['nonce'],
        super.verified();

  @override
  KbJws sign(
      {required Jwk jsonWebKey,
      JwsJoseHeader? header,
      SigningAlgorithm? signingAlgorithm}) {
    Jws jws =
        super.sign(jsonWebKey: jsonWebKey, signingAlgorithm: signingAlgorithm);
    return KbJws(
        payload: jws.payload, signature: jws.signature, header: jws.header);
  }
}
