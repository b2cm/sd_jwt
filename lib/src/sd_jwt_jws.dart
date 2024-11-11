import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:json_path/json_path.dart';
import 'package:sd_jwt/sd_jwt.dart';
import 'package:sd_jwt/src/sd_jwt_utils.dart';

class SdJws extends Jws {
  Disclosures? _disclosures;
  KbJws? keyBindingJws;
  DigestAlgorithm _digestAlgorithm;

  Disclosures? get disclosures => _disclosures;

  SdJws({
    required super.payload,
    required super.signature,
    required super.protected,
    required super.header,
    Disclosures? disclosures,
    this.keyBindingJws,
    required DigestAlgorithm digestAlgorithm,
  })  : _digestAlgorithm = digestAlgorithm,
        _disclosures = disclosures;

  factory SdJws.fromCompactSerialization(String string) {
    List<Uint8List> disclosures = [];
    List<String> elements = string.split('~');

    Jws jws = Jws.fromCompactSerialization(elements.first);
    DigestAlgorithm digestAlgorithm = DigestAlgorithm.values.singleWhere(
        (e) => e.name == json.decode(utf8.decode(jws.payload))['_sd_alg']);

    for (int i = 1; i < elements.length - 1; i++) {
      disclosures.add(base64Url.decode(addPaddingToBase64(elements[i])));
    }

    KbJws? kbJws;
    if (elements.last.isNotEmpty) {
      kbJws = KbJws.fromCompactSerialization(elements.last);
    }

    return SdJws(
        payload: jws.payload,
        signature: jws.signature,
        header: jws.header,
        protected: jws.protected,
        disclosures: Disclosures.fromBytes(disclosures),
        keyBindingJws: kbJws,
        digestAlgorithm: digestAlgorithm);
  }

  @override
  String toCompactSerialization() {
    String compactSerialization = '${super.toCompactSerialization()}~';
    _disclosures != null
        ? compactSerialization +=
            '${_disclosures!.origin.map((e) => removePaddingFromBase64(base64Url.encode(e))).join('~')}~'
        : null;
    keyBindingJws != null
        ? compactSerialization += keyBindingJws!.toCompactSerialization()
        : null;
    return compactSerialization;
  }

  @override
  Map<String, dynamic> toJson() {
    Map<String, dynamic> map = super.toJson();
    map.addAll({
      'disclosures': _disclosures?.origin
          .map((e) => removePaddingFromBase64(base64Url.encode(e)))
          .toList(),
    });
    if (keyBindingJws != null) {
      map.addAll({
        'keybinding_jws': keyBindingJws!.toJson(),
      });
    }
    return map;
  }

  @override
  Map<String, dynamic> jsonContent() {
    Map<String, dynamic> map = super.jsonContent();
    map.addAll({
      'disclosures': _disclosures,
    });
    if (keyBindingJws != null) {
      map.addAll({
        'keybinding_jws': keyBindingJws!.jsonContent(),
      });
    }
    return map;
  }

  List<String> _findParentKeys(JsonPath path, SdJwt sdJwt) {
    List<String> salts = [];
    String jp = path.toString();
    var split = jp.split('.');
    if (split.length > 2) {
      split.removeLast();
      split.removeAt(0);
      return split;
    } else if (split.length == 2) {
      split.removeAt(0);
      return split;
    }

    return salts;
  }

  SdJws disclose(List<JsonPath> toDisclose) {
    if (disclosures == null || disclosures!.isEmpty) {
      // Nothing to disclose
      return this;
    }

    var sdJwt = toSdJwt();
    List<String> disclosureKeys = [];
    List<String> disclosureSalts = []; // Used for list elements

    for (var path in toDisclose) {
      var match = path.read(sdJwt.disclosures);
      if (match.isNotEmpty) {
        for (var m in match) {
          if (m.value is Disclosure) {
            var parsedDisclosure = m.value as Disclosure;
            if (parsedDisclosure.key != null) {
              disclosureKeys.add(parsedDisclosure.key!);
            } else {
              disclosureSalts.add(parsedDisclosure.salt);
            }
            disclosureKeys.addAll(_findParentKeys(path, sdJwt));
          } else if (m.value is List) {
            for (var element in m.value as List) {
              if (element is Disclosure) {
                if (element.key != null) {
                  disclosureKeys.add(element.key!);
                } else {
                  disclosureSalts.add(element.salt);
                }
              }
            }
          } else if (m.value is Map) {
            // here we assume there is an object which should be disclosed
            for (var entry in (m.value as Map).entries) {
              if (entry.value is Disclosure) {
                var parsedDisclosure = entry.value as Disclosure;
                if (parsedDisclosure.key != null) {
                  disclosureKeys.add(parsedDisclosure.key!);
                } else {
                  disclosureSalts.add(parsedDisclosure.salt);
                }
                disclosureKeys.addAll(_findParentKeys(path, sdJwt));
              } else if (entry.value is List) {
                for (var element in entry.value) {
                  if (element is Disclosure) {
                    if (element.key != null) {
                      disclosureKeys.add(element.key!);
                    } else {
                      disclosureSalts.add(element.salt);
                    }
                  }
                }
              }
            }
          }
        }
      }
    }

    List<Uint8List> foundDisclosures = [];
    for (int i = 0; i < disclosures!.length; i++) {
      var d = disclosures![i];
      if (d.key != null && disclosureKeys.contains(d.key)) {
        foundDisclosures.add(disclosures!.origin[i]);
      } else if (disclosureSalts.contains(d.salt)) {
        foundDisclosures.add(disclosures!.origin[i]);
      }
    }

    return SdJws(
        payload: payload,
        signature: signature,
        protected: protected,
        header: header,
        digestAlgorithm: _digestAlgorithm,
        disclosures: Disclosures.fromBytes(foundDisclosures));
  }

  SdJwt toSdJwt() => SdJwt.fromSdJws(this);

  Uint8List get digest {
    String compactSerialization = super.toCompactSerialization();
    _disclosures != null
        ? compactSerialization +=
            '~${_disclosures!.origin.map((e) => removePaddingFromBase64(base64Url.encode(e))).join('~')}'
        : null;
    PointyCastleCryptoProvider pointyCastleCryptoProvider =
        PointyCastleCryptoProvider();
    Uint8List digestInput = ascii.encode(compactSerialization);
    return pointyCastleCryptoProvider.digest(
        data: digestInput, algorithm: _digestAlgorithm);
  }

  FutureOr<SdJws> bind(
      {required CryptoProvider signer,
      required String audience,
      required DateTime issuedAt,
      required String nonce,
      SigningAlgorithm? signingAlgorithm,
      DigestAlgorithm? digestAlgorithm}) async {
    Uint8List sdHash = digest;

    KbJws kbJws = await KbJwt(
            audience: audience,
            issuedAt: issuedAt,
            nonce: nonce,
            sdHash: sdHash)
        .sign(signer: signer, signingAlgorithm: signingAlgorithm);
    keyBindingJws = kbJws;
    return this;
  }
}

class Jws {
  Uint8List payload;
  Map<String, dynamic> header;
  Uint8List protected;
  Uint8List signature;

  Jws({
    required this.payload,
    required this.signature,
    required this.header,
    required this.protected,
  });

  factory Jws.fromCompactSerialization(String string) {
    Uint8List protected =
        base64Url.decode(addPaddingToBase64(string.split('.')[0]));
    Uint8List payload =
        base64Url.decode(addPaddingToBase64(string.split('.')[1]));
    Uint8List signature =
        base64Url.decode(addPaddingToBase64(string.split('.')[2]));

    return Jws(
        payload: payload,
        signature: signature,
        protected: protected,
        header: {});
  }

/*  RFC 7515                JSON Web Signature (JWS)                May 2015

  2.  Terminology

    Base64url Encoding
      Base64 encoding using the URL- and filename-safe character set
      defined in Section 5 of RFC 4648 [RFC4648], with all trailing '='
      characters omitted (as permitted by Section 3.2) and without the
      inclusion of any line breaks, whitespace, or other additional
      characters.  Note that the base64url encoding of the empty octet
      sequence is the empty string.  (See Appendix C for notes on
      implementing base64url encoding without padding.)

  3.1.  JWS Compact Serialization Overview

   In the JWS Compact Serialization, no JWS Unprotected Header is used.
   In this case, the JOSE Header and the JWS Protected Header are the
   same.

   In the JWS Compact Serialization, a JWS is represented as the
   concatenation:

      BASE64URL(UTF8(JWS Protected Header)) || '.' ||
      BASE64URL(JWS Payload) || '.' ||
      BASE64URL(JWS Signature)

   See Section 7.1 for more information about the JWS Compact
   Serialization.

  7.1.  JWS Compact Serialization

   The JWS Compact Serialization represents digitally signed or MACed
   content as a compact, URL-safe string.  This string is:

      BASE64URL(UTF8(JWS Protected Header)) || '.' ||
      BASE64URL(JWS Payload) || '.' ||
      BASE64URL(JWS Signature)

   Only one signature/MAC is supported by the JWS Compact Serialization
   and it provides no syntax to represent a JWS Unprotected Header
   value.*/

  String toCompactSerialization() {
    String jwsHeader = removePaddingFromBase64(base64Url.encode(protected));
    String jwsPayload = removePaddingFromBase64(base64Url.encode(payload));
    String jwsSignature = removePaddingFromBase64(base64Url.encode(signature));

    return '$jwsHeader.$jwsPayload.$jwsSignature';
  }

  // Jws.fromJson(Map<String, dynamic> map)
  //     : payload = json.decode(utf8.decode(base64Url.decode(addPaddingToBase64(map['payload'])))),
  //       header = JwsJoseHeader(algorithm: SigningAlgorithm.es256),
  //       signature = base64.decode(addPaddingToBase64(map['signature'])) {
  // }

/*  RFC 7515                JSON Web Signature (JWS)                May 2015

  2.  Terminology

  3.2.  JWS JSON Serialization Overview

  In the JWS JSON Serialization, one or both of the JWS Protected
  Header and JWS Unprotected Header MUST be present.  In this case, the
  members of the JOSE Header are the union of the members of the JWS
  Protected Header and the JWS Unprotected Header values that are
  present.

  In the JWS JSON Serialization, a JWS is represented as a JSON object
  containing some or all of these four members:

  o  "protected", with the value BASE64URL(UTF8(JWS Protected Header))
  o  "header", with the value JWS Unprotected Header
  o  "payload", with the value BASE64URL(JWS Payload)
  o  "signature", with the value BASE64URL(JWS Signature)

  The three base64url-encoded result strings and the JWS Unprotected
  Header value are represented as members within a JSON object.  The
  inclusion of some of these values is OPTIONAL.  The JWS JSON
  Serialization can also represent multiple signature and/or MAC
  values, rather than just one.  See Section 7.2 for more information
  about the JWS JSON Serialization.*/

  Map<String, dynamic> toJson() => {
        'protected': removePaddingFromBase64(base64Url.encode(protected)),
        'header': header,
        'payload': removePaddingFromBase64(base64Url.encode(payload)),
        'signature': removePaddingFromBase64(base64Url.encode(signature)),
      };

  Map<String, dynamic> jsonContent() => {
        'protected': json.decode(utf8.decode(protected)),
        'header': header,
        'payload': json.decode(utf8.decode(payload)),
        'signature': signature,
      };

  FutureOr<bool> verify(CryptoProvider verifier) {
    var jwt = toJwt();
    return jwt.verify(this, verifier);
  }

  @override
  String toString() => toJson().toString();

  Jwt toJwt() => Jwt.fromJws(this);
}

class KbJws extends Jws {
  KbJws({
    required super.payload,
    required super.signature,
    required super.header,
    required super.protected,
  });

  factory KbJws.fromCompactSerialization(String string) {
    Uint8List protected =
        base64Url.decode(addPaddingToBase64(string.split('.')[0]));
    Uint8List payload =
        base64Url.decode(addPaddingToBase64(string.split('.')[1]));
    Uint8List signature =
        base64Url.decode(addPaddingToBase64(string.split('.')[2]));

    return KbJws(
      payload: payload,
      signature: signature,
      protected: protected,
      header: {},
    );
  }

  KbJwt toKbJwt() {
    return KbJwt.fromJws(this);
  }
}
