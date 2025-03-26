import 'dart:async';
import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

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
    required Map<String, dynamic> claims,
    Map<String, dynamic>? alwaysDisclosed,
    SaltAlgorithm saltAlgorithm = SaltAlgorithm.randomBase64UrlNoPadding256,
    DigestAlgorithm digestAlgorithm = DigestAlgorithm.sha2_256,
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
    super.additionalClaims = _deepCopyMap(claims);
    _parseRegisteredClaims();
    _removeRegisteredClaims();
    _disclosures = _createDisclosuresMap(
        super.additionalClaims!, saltAlgorithm, digestAlgorithm);
    alwaysDisclosed != null ? _alwaysDisclosed = alwaysDisclosed : null;
  }

  /// Parse SDJws to SDJwt
  SdJwt.fromSdJws(SdJws sdJws)
      : _digestAlgorithm = DigestAlgorithm.values.singleWhere((e) =>
            e.name == json.decode(utf8.decode(sdJws.payload))['_sd_alg']),
        decoyFactor = DecoyFactor.none,
        super.fromJws(sdJws) {
    additionalClaims?.remove('_sd_alg');

    if (sdJws.disclosures != null) {
      _disclosures = _deepCopyMap(additionalClaims ?? {});
      _disclosures = _restoreDisclosuresMap(_disclosures, sdJws.disclosures!);
      additionalClaims = _deepCopyMap(_disclosures);
      additionalClaims = _restoreClaimsMap(additionalClaims ?? {});
    }
  }

  /// Parse Json Representation of SDJwt
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
      _disclosures = _deepCopyMap(additionalClaims ?? {});
      _disclosures =
          _restoreDisclosuresMap(_disclosures, Disclosures(disclosuresList));
      additionalClaims = _deepCopyMap(_disclosures);
      additionalClaims = _restoreClaimsMap(additionalClaims ?? {});
    }
  }

  /// Builds disclosures from payload, except registered claims.
  ///
  /// Salt algorithm can be set by SaltAlgorithm object. Defaults to Base64Url
  /// encoded random data with length of 256 bits. Padding will be removed.
  void build({SaltAlgorithm? saltAlgorithm}) {
    _disclosures = _createDisclosuresMap(
        super.payload,
        saltAlgorithm ??
            _saltAlgorithm ??
            SaltAlgorithm.randomBase64UrlNoPadding256,
        _digestAlgorithm);
  }

  @override

  /// Signs this SD-JWT and returns a SD-JWS
  ///
  /// Either a JWS-Header must be set (during generation of this sd-jwt or
  /// with [header] parameter) or [signingAlgorithm] must be given.
  FutureOr<SdJws> sign(
      {required CryptoProvider signer,
      JwsJoseHeader? header,
      SigningAlgorithm? signingAlgorithm}) async {
    List<Disclosure> disclosuresList = [];
    _getDisclosuresMap(_disclosures, disclosuresList);
    Jws jws = await super.sign(
        signer: signer, header: header, signingAlgorithm: signingAlgorithm);
    return SdJws(
      payload: jws.payload,
      signature: jws.signature,
      protected: jws.protected,
      header: jws.header,
      disclosures: Disclosures(disclosuresList),
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

  Uint8List _digest(Uint8List digestInput) {
    return generateDigest(
        data: ascii
            .encode(removePaddingFromBase64(base64Url.encode(digestInput))),
        algorithm: _digestAlgorithm);
  }

  _restoreDisclosuresMap(Map<String, dynamic> map, Disclosures disclosures) {
    Map<String, dynamic> tmp = {};

    for (MapEntry entry in map.entries) {
      if (entry.key == '_sd') {
        for (Uint8List disclosure in disclosures.origin) {
          if ((entry.value as List).contains(
              removePaddingFromBase64(base64Url.encode(_digest(disclosure))))) {
            Disclosure disclosureObject = Disclosure.fromBytes(disclosure);
            if (disclosureObject.value is Map &&
                disclosureObject.value.containsKey('_sd')) {
              tmp[disclosureObject.key!] =
                  _restoreDisclosuresMap(disclosureObject.value, disclosures);
            } else {
              tmp[disclosureObject.key!] = disclosureObject;
            }
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

  _restoreDisclosuresList(List<dynamic> list, Disclosures disclosures) {
    List removals = [];
    for (dynamic entry in list) {
      if (entry is Map<String, dynamic>) {
        if (entry.containsKey('...')) {
          bool found = false;
          for (Uint8List disclosure in disclosures.origin) {
            if (entry['...'] ==
                removePaddingFromBase64(
                    base64Url.encode(_digest(disclosure)))) {
              Disclosure disclosureObject = Disclosure.fromBytes(disclosure);
              list[list.indexOf(entry)] = disclosureObject;
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
  Map<String, dynamic>? additionalClaims;
  String? issuer;
  String? subject;
  String? audience;
  DateTime? expirationTime;
  DateTime? notBefore;
  DateTime? issuedAt;
  String? jwtId;
  Confirmation? confirmation;
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

  JoseHeader get header => _header;

  Map<String, dynamic> get payload {
    Map<String, dynamic> map = additionalClaims == null
        ? <String, dynamic>{}
        : Map<String, dynamic>.of(additionalClaims!);
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
      {this.confirmation,
      this.additionalClaims,
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
      : additionalClaims = Map.of(map['payload']),
        _header = JoseHeader.fromJson(map['header']) {
    _parseRegisteredClaims();
    _removeRegisteredClaims();
  }

  Jwt.fromJws(Jws jsonWebSignature)
      : additionalClaims =
            Map.of(json.decode(utf8.decode(jsonWebSignature.payload))),
        _header = JoseHeader.fromJson(
            json.decode(utf8.decode(jsonWebSignature.protected))) {
    _parseRegisteredClaims();
    _removeRegisteredClaims();
  }

  FutureOr<bool> verify(Jws jsonWebSignature, CryptoProvider verifier) {
    Uint8List signature = jsonWebSignature.signature;
    Uint8List verificationInput = RFC7515.verificationInput(
        payload: jsonWebSignature.payload,
        protectedHeader: jsonWebSignature.protected);

    var sig = Signature.fromSignatureBytes(
        signature, (_header as JwsJoseHeader).algorithm);

    return verifier.verify(
        data: verificationInput,
        algorithm: (_header).algorithm,
        signature: sig);
  }

  /// Signs this JWT and returns a JWS
  ///
  /// Either a JWS-Header must be set (during generation of this jwt or
  /// with [header] parameter) or [signingAlgorithm] must be given.
  FutureOr<Jws> sign(
      {required CryptoProvider signer,
      JwsJoseHeader? header,
      SigningAlgorithm? signingAlgorithm}) async {
    JwsJoseHeader jwsHeader;
    if (_header is JwsJoseHeader) {
      jwsHeader = _header;
    } else if (header != null) {
      jwsHeader = header;
    } else if (signingAlgorithm != null) {
      jwsHeader = JwsJoseHeader(
        algorithm: signingAlgorithm,
        type: _header.type,
        contentType: _header.contentType,
      );
    } else {
      throw Exception('Neither singing algorithm nor header parameters set');
    }

    signingAlgorithm = jwsHeader.algorithm;

    Map<String, dynamic> payload = Map.of(this.payload);

    Uint8List signingInput = RFC7515.signingInput(
        protectedHeader: jwsHeader.toJson(), payload: payload);

    Signature signature =
        await signer.sign(data: signingInput, algorithm: signingAlgorithm);

    return Jws(
      payload: RFC7515.bytes(payload),
      signature: signature.toSignatureBytes(),
      header: {},
      protected: RFC7515.bytes(jwsHeader.toJson()),
    );
  }

  Map<String, dynamic> toJson() =>
      {'header': _header.toJson(), 'payload': payload};

  /// Returns the json encoded representation
  String toJsonString() => json.encode(toJson());

  @override
  String toString() => toJson().toString();

  void _parseRegisteredClaims() {
    if (subject == null && additionalClaims?['sub'] != null) {
      subject = additionalClaims!['sub'];
    }
    if (issuer == null && additionalClaims?['iss'] != null) {
      issuer = additionalClaims!['iss'];
    }
    if (audience == null && additionalClaims?['aud'] != null) {
      audience = additionalClaims!['aud'];
    }
    if (expirationTime == null && additionalClaims?['exp'] != null) {
      try {
        expirationTime = DateTime.fromMillisecondsSinceEpoch(
            additionalClaims!['exp'] * 1000);
      } on Exception {
        rethrow;
      }
    }
    if (notBefore == null && additionalClaims?['nbf'] != null) {
      try {
        notBefore = DateTime.fromMillisecondsSinceEpoch(
            additionalClaims!['nbf'] * 1000);
      } on Exception {
        rethrow;
      }
    }
    if (issuedAt == null && additionalClaims?['iat'] != null) {
      try {
        issuedAt = DateTime.fromMillisecondsSinceEpoch(
            additionalClaims!['iat'] * 1000);
      } on Exception {
        rethrow;
      }
    }
    if (jwtId == null && additionalClaims?['jti'] != null) {
      jwtId = additionalClaims!['jti'];
    }
    if (confirmation == null && additionalClaims?['cnf'] != null) {
      if (additionalClaims!['cnf'] is Map &&
          (additionalClaims!['cnf'] as Map).containsKey('jwk')) {
        confirmation = JwkConfirmation.fromJson(additionalClaims!['cnf']);
      }
    }
  }

  void _removeRegisteredClaims() {
    additionalClaims?.remove('sub');
    additionalClaims?.remove('iss');
    additionalClaims?.remove('aud');
    additionalClaims?.remove('exp');
    additionalClaims?.remove('nbf');
    additionalClaims?.remove('iat');
    additionalClaims?.remove('jti');
    additionalClaims?.remove('cnf');
  }
}

class Disclosures implements List<Disclosure> {
  List<Uint8List> origin;

  List<Disclosure> get elements =>
      origin.map((e) => Disclosure.fromBytes(e)).toList();

  Disclosures(List<Disclosure> elements)
      : length = elements.length,
        origin = elements.map((e) => e.bytes).toList();

  Disclosures.fromBytes(List<Uint8List> disclosures)
      : length = disclosures.length,
        origin = disclosures;

  @override
  int length;

  @override
  Disclosure operator [](int index) {
    return elements.elementAt(index);
  }

  @override
  void operator []=(int index, Disclosure value) {
    origin[index] = value.bytes;
  }

  @override
  bool remove(Object? element) {
    if (element is Disclosure) {
      Uint8List? toRemove;
      for (Uint8List disclosure in origin) {
        Disclosure disclosureObject = Disclosure.fromBytes(disclosure);
        if (disclosureObject.salt == element.salt &&
            disclosureObject.key == element.key &&
            disclosureObject.value == element.value) {
          toRemove = disclosure;
        }
      }
      if (toRemove != null) {
        origin.remove(toRemove);
        return true;
      }
    }
    return false;
  }

  @override
  Disclosure get first => Disclosure.fromBytes(origin.first);

  @override
  Disclosure get last => Disclosure.fromBytes(origin.last);

  @override
  set first(Disclosure value) {
    origin.first = value.bytes;
  }

  @override
  set last(Disclosure value) {
    origin.last = value.bytes;
  }

  @override
  List<Disclosure> operator +(List<Disclosure> other) {
    origin.addAll(other.map((e) => e.bytes));
    return origin.map((e) => Disclosure.fromBytes(e)).toList();
  }

  @override
  void add(Disclosure value) {
    origin.add(value.bytes);
  }

  @override
  void addAll(Iterable<Disclosure> iterable) {
    origin.addAll(iterable.map((e) => e.bytes));
  }

  @override
  bool any(bool Function(Disclosure element) test) {
    return origin.map((e) => Disclosure.fromBytes(e)).any(test);
  }

  @override
  Map<int, Disclosure> asMap() {
    return origin.map((e) => Disclosure.fromBytes(e)).toList().asMap();
  }

  @override
  List<R> cast<R>() {
    return origin.map((e) => Disclosure.fromBytes(e)).cast<R>().toList();
  }

  @override
  void clear() {
    origin.clear();
  }

  @override
  bool contains(Object? element) {
    if (element is Disclosure) {
      for (int i = 0; i < length; i++) {
        if (this[i].key == element.key &&
            this[i].value == element.value &&
            this[i].salt == element.salt) {
          return true;
        }
      }
    }
    return false;
  }

  @override
  Disclosure elementAt(int index) {
    return Disclosure.fromBytes(origin.elementAt(index));
  }

  @override
  bool every(bool Function(Disclosure element) test) {
    return origin.map((e) => Disclosure.fromBytes(e)).every(test);
  }

  @override
  Iterable<T> expand<T>(Iterable<T> Function(Disclosure element) toElements) {
    return origin.map((e) => Disclosure.fromBytes(e)).expand(toElements);
  }

  @override
  void fillRange(int start, int end, [Disclosure? fillValue]) {
    origin.fillRange(start, end, fillValue?.bytes);
  }

  @override
  Disclosure firstWhere(bool Function(Disclosure element) test,
      {Disclosure Function()? orElse}) {
    return origin.map((e) => Disclosure.fromBytes(e)).firstWhere(test);
  }

  @override
  T fold<T>(
      T initialValue, T Function(T previousValue, Disclosure element) combine) {
    return origin
        .map((e) => Disclosure.fromBytes(e))
        .fold(initialValue, combine);
  }

  @override
  Iterable<Disclosure> followedBy(Iterable<Disclosure> other) {
    return origin.map((e) => Disclosure.fromBytes(e)).followedBy(other);
  }

  @override
  void forEach(void Function(Disclosure element) action) {
    for (int i = 0; i < length; i++) {
      action(this[i]);
    }
  }

  @override
  Iterable<Disclosure> getRange(int start, int end) {
    return origin
        .map((e) => Disclosure.fromBytes(e))
        .toList()
        .getRange(start, end);
  }

  @override
  int indexOf(Disclosure element, [int start = 0]) {
    for (int i = start; i < length; i++) {
      if (this[i].key == element.key &&
          this[i].value == element.value &&
          this[i].salt == element.salt) {
        return i;
      }
    }
    return -1;
  }

  @override
  int indexWhere(bool Function(Disclosure element) test, [int start = 0]) {
    return origin.map((e) => Disclosure.fromBytes(e)).toList().indexWhere(test);
  }

  @override
  void insert(int index, Disclosure element) {
    origin.insert(index, element.bytes);
  }

  @override
  void insertAll(int index, Iterable<Disclosure> iterable) {
    origin.insertAll(index, iterable.map((e) => e.bytes));
  }

  @override
  bool get isEmpty => origin.isEmpty;

  @override
  bool get isNotEmpty => origin.isNotEmpty;

  @override
  Iterator<Disclosure> get iterator =>
      origin.map((e) => Disclosure.fromBytes(e)).iterator;

  @override
  String join([String separator = ""]) {
    return origin.map((e) => Disclosure.fromBytes(e)).join(separator);
  }

  @override
  int lastIndexOf(Disclosure element, [int? start]) {
    for (Uint8List disclosure in origin) {
      Disclosure disclosureObject = Disclosure.fromBytes(disclosure);
      if (disclosureObject.key == element.key &&
          disclosureObject.value == element.value &&
          disclosureObject.salt == element.salt) {
        return origin.lastIndexOf(disclosure);
      }
    }
    return -1;
  }

  @override
  int lastIndexWhere(bool Function(Disclosure element) test, [int? start]) {
    return origin
        .map((e) => Disclosure.fromBytes(e))
        .toList()
        .lastIndexWhere(test);
  }

  @override
  Disclosure lastWhere(bool Function(Disclosure element) test,
      {Disclosure Function()? orElse}) {
    return origin.map((e) => Disclosure.fromBytes(e)).lastWhere(test);
  }

  @override
  Iterable<T> map<T>(T Function(Disclosure e) toElement) {
    return origin.map((e) => Disclosure.fromBytes(e)).map(toElement);
  }

  @override
  Disclosure reduce(
      Disclosure Function(Disclosure value, Disclosure element) combine) {
    return origin.map((e) => Disclosure.fromBytes(e)).reduce(combine);
  }

  @override
  Disclosure removeAt(int index) {
    return Disclosure.fromBytes(origin.removeAt(index));
  }

  @override
  Disclosure removeLast() {
    return Disclosure.fromBytes(origin.removeLast());
  }

  @override
  void removeRange(int start, int end) {
    origin.removeRange(start, end);
  }

  @override
  void removeWhere(bool Function(Disclosure element) test) {
    for (int i = 0; i < length; i++) {
      if (test(this[i])) {
        origin.removeAt(i);
      }
    }
  }

  @override
  void replaceRange(int start, int end, Iterable<Disclosure> replacements) {
    origin.replaceRange(start, end, replacements.map((e) => e.bytes));
  }

  @override
  void retainWhere(bool Function(Disclosure element) test) {
    _filter(test, true);
  }

  void _filter(bool Function(Disclosure element) test, bool retainMatching) {
    List<Disclosure> retained = <Disclosure>[];
    int length = this.length;
    for (int i = 0; i < length; i++) {
      var element = this[i];
      if (test(element) == retainMatching) {
        retained.add(element);
      }
      if (length != this.length) {
        throw ConcurrentModificationError(this);
      }
    }
    if (retained.length != this.length) {
      setRange(0, retained.length, retained);
      this.length = retained.length;
    }
  }

  @override
  Iterable<Disclosure> get reversed =>
      origin.map((e) => Disclosure.fromBytes(e)).toList().reversed;

  @override
  void setAll(int index, Iterable<Disclosure> iterable) {
    origin.setAll(index, iterable.map((e) => e.bytes));
  }

  @override
  void setRange(int start, int end, Iterable<Disclosure> iterable,
      [int skipCount = 0]) {
    origin.setRange(start, end, iterable.map((e) => e.bytes), skipCount);
  }

  @override
  void shuffle([Random? random]) {
    origin.shuffle(random);
  }

  @override
  Disclosure get single => origin.map((e) => Disclosure.fromBytes(e)).single;

  @override
  Disclosure singleWhere(bool Function(Disclosure element) test,
      {Disclosure Function()? orElse}) {
    return origin.map((e) => Disclosure.fromBytes(e)).singleWhere(test);
  }

  @override
  Iterable<Disclosure> skip(int count) {
    return origin.map((e) => Disclosure.fromBytes(e)).skip(count);
  }

  @override
  Iterable<Disclosure> skipWhile(bool Function(Disclosure value) test) {
    return origin.map((e) => Disclosure.fromBytes(e)).skipWhile(test);
  }

  @override
  void sort([int Function(Disclosure a, Disclosure b)? compare]) {
    throw UnimplementedError();
  }

  @override
  List<Disclosure> sublist(int start, [int? end]) {
    return origin
        .map((e) => Disclosure.fromBytes(e))
        .toList()
        .sublist(start, end);
  }

  @override
  Iterable<Disclosure> take(int count) {
    return origin.map((e) => Disclosure.fromBytes(e)).toList().take(count);
  }

  @override
  Iterable<Disclosure> takeWhile(bool Function(Disclosure value) test) {
    return origin.map((e) => Disclosure.fromBytes(e)).takeWhile(test);
  }

  @override
  List<Disclosure> toList({bool growable = true}) {
    return origin
        .map((e) => Disclosure.fromBytes(e))
        .toList(growable: growable);
  }

  @override
  Set<Disclosure> toSet() {
    return origin.map((e) => Disclosure.fromBytes(e)).toSet();
  }

  @override
  Iterable<Disclosure> where(bool Function(Disclosure element) test) {
    return origin.map((e) => Disclosure.fromBytes(e)).where(test);
  }

  @override
  Iterable<T> whereType<T>() {
    throw UnimplementedError();
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
    return generateDigest(
        data: ascii.encode(removePaddingFromBase64(base64Url.encode(bytes))),
        algorithm: digestAlgorithm);
  }

  Disclosure(
      {this.key,
      this.value,
      String? salt,
      SaltAlgorithm? saltAlgorithm,
      DigestAlgorithm digestAlgorithm = DigestAlgorithm.sha2_256})
      : salt = salt ??= SaltValue(
                saltAlgorithm ?? SaltAlgorithm.randomBase64UrlNoPadding256)
            .value;

  Disclosure.fromJson(Map<String, dynamic> map)
      : salt = map['salt'],
        key = map['key'],
        value = map['value'];

  factory Disclosure.fromBytes(Uint8List disclosure) {
    dynamic decoded = json.decode(utf8.decode(disclosure));
    if (decoded is List) {
      if (decoded.length == 2) {
        return Disclosure(
          salt: decoded[0],
          value: decoded[1],
        );
      } else if (decoded.length == 3) {
        return Disclosure(
          salt: decoded[0],
          key: decoded[1],
          value: decoded[2],
        );
      } else {
        throw Exception('Invalid disclosure.');
      }
    }
    throw Exception('Invalid disclosure.');
  }

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

  /// generate a random salt with [length] and encode it base64(url)
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
        'sd_hash': removePaddingFromBase64(base64Url.encode(sdHash)),
      });
  }

  KbJwt(
      {required super.audience,
      required super.issuedAt,
      required this.nonce,
      required this.sdHash})
      : super() {
    issuedAt ??= DateTime.now();
  }

  KbJwt.fromJws(super.jsonWebSignature)
      : sdHash = base64Url.decode(addPaddingToBase64(
            json.decode(utf8.decode(jsonWebSignature.payload))['sd_hash'])),
        nonce = json.decode(utf8.decode(jsonWebSignature.payload))['nonce'],
        super.fromJws();

  @override
  FutureOr<KbJws> sign(
      {required CryptoProvider signer,
      JwsJoseHeader? header,
      SigningAlgorithm? signingAlgorithm}) async {
    Jws jws = await super.sign(
        signer: signer,
        signingAlgorithm: signingAlgorithm,
        header: JwsJoseHeader(
            type: 'kb+jwt',
            algorithm: signingAlgorithm ?? SigningAlgorithm.eddsa25519Sha512));
    return KbJws(
        payload: jws.payload,
        signature: jws.signature,
        protected: jws.protected,
        header: jws.header);
  }
}
