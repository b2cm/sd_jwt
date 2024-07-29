import 'dart:convert';
import 'dart:typed_data';

import 'package:sd_jwt/sd_jwt.dart';
import 'package:sd_jwt/src/crypto_provider/pointycastle_crypto_provider.dart';
import 'package:sd_jwt/src/sd_jwt_crypto_provider.dart';
import 'package:sd_jwt/src/sd_jwt_jose.dart';
import 'package:sd_jwt/src/sd_jwt_jwk.dart';
import 'package:sd_jwt/src/sd_jwt_utils.dart';

class SdJws extends Jws {
  List<Disclosure>? disclosures;
  KbJws? keyBindingJws;
  DigestAlgorithm _digestAlgorithm;

  SdJws({
    required super.payload,
    required super.signature,
    required super.header,
    this.disclosures,
    this.keyBindingJws,
    required DigestAlgorithm digestAlgorithm,
  }) : _digestAlgorithm = digestAlgorithm;

  factory SdJws.fromCompactSerialization(String string) {
    List<Disclosure> disclosures = [];
    List<String> elements = string.split('~');

    String compactJws = elements.first;
    List<String> other = elements.sublist(1, elements.length);

    Jws jws = Jws.fromCompactSerialization(compactJws);
    DigestAlgorithm digestAlgorithm = DigestAlgorithm.values
        .singleWhere((e) => e.name == jws.payload['_sd_alg']);

    KbJws? kbJws;
    for (String element in other) {
      if (element.startsWith('Wy')) {
        List decoded = json
            .decode(utf8.decode(base64Url.decode(addPaddingToBase64(element))));
        if (decoded.length == 2) {
          disclosures.add(Disclosure(salt: decoded[0], value: decoded[1]));
        } else if (decoded.length == 3) {
          disclosures.add(
              Disclosure(salt: decoded[0], key: decoded[1], value: decoded[2]));
        }
      } else if (element.startsWith('ey') && element.contains('.')) {
        kbJws = KbJws.fromCompactSerialization(element);
      }
    }

    return SdJws(
        payload: jws.payload,
        signature: jws.signature,
        header: jws.header,
        disclosures: disclosures,
        keyBindingJws: kbJws,
        digestAlgorithm: digestAlgorithm);
  }

  @override
  String toCompactSerialization() {
    String compactSerialization = super.toCompactSerialization();
    disclosures != null
        ? compactSerialization +=
            '~${disclosures!.map((e) => removePaddingFromBase64(base64Url.encode(e.bytes))).join('~')}'
        : null;
    keyBindingJws != null
        ? compactSerialization += '~${keyBindingJws!.toCompactSerialization()}'
        : null;
    return compactSerialization;
  }

  @override
  Map<String, dynamic> toJson() {
    Map<String, dynamic> map = super.toJson();
    map.addAll({
      'disclosures': disclosures
          ?.map((e) => removePaddingFromBase64(base64Url.encode(e.bytes)))
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
      'disclosures': disclosures,
    });
    if (keyBindingJws != null) {
      map.addAll({
        'keybinding_jws': keyBindingJws!.jsonContent(),
      });
    }
    return map;
  }

  @override
  SdJwt verified(Jwk jsonWebKey) {
    return SdJwt.verified(this, jsonWebKey);
  }

  @override
  bool verify(Jwk jsonWebKey) {
    try {
      SdJwt.verified(this, jsonWebKey);
      return true;
    } on Exception {
      return false;
    }
  }

  Uint8List get digest {
    String compactSerialization = super.toCompactSerialization();
    disclosures != null
        ? compactSerialization +=
            '~${disclosures!.map((e) => removePaddingFromBase64(base64Url.encode(e.bytes))).join('~')}'
        : null;
    PointyCastleCryptoProvider pointyCastleCryptoProvider =
        PointyCastleCryptoProvider();
    Uint8List digestInput = ascii.encode(compactSerialization);
    return pointyCastleCryptoProvider.digest(
        data: digestInput, algorithm: _digestAlgorithm);
  }

  SdJws bind(
      {required Jwk jsonWebKey,
      required String audience,
      required DateTime issuedAt,
      required String nonce,
      SigningAlgorithm? signingAlgorithm,
      DigestAlgorithm? digestAlgorithm}) {
    Uint8List sdHash = digest;

    KbJws kbJws = KbJwt(
            audience: audience,
            issuedAt: issuedAt,
            nonce: nonce,
            sdHash: sdHash)
        .sign(jsonWebKey: jsonWebKey, signingAlgorithm: signingAlgorithm);
    return SdJws(
      payload: payload,
      signature: signature,
      header: header,
      disclosures: disclosures,
      keyBindingJws: kbJws,
      digestAlgorithm: _digestAlgorithm,
    );
  }
}

class Jws {
  Map<String, dynamic> payload;
  JwsJoseHeader header;
  Uint8List signature;

  Jws({
    required this.payload,
    required this.signature,
    required this.header,
  });

  factory Jws.fromCompactSerialization(String string) {
    Map<String, dynamic> protected = json.decode(utf8
        .decode(base64Url.decode(addPaddingToBase64(string.split('.')[0]))));
    Map<String, dynamic> payload = json.decode(utf8
        .decode(base64Url.decode(addPaddingToBase64(string.split('.')[1]))));
    Uint8List signature =
        base64Url.decode(addPaddingToBase64(string.split('.')[2]));

    return Jws(
        payload: payload,
        signature: signature,
        header: JwsJoseHeader.fromJson({'protected': protected}));
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
    String jwsHeader = removePaddingFromBase64(
        base64Url.encode(utf8.encode(json.encode(header.protected))));
    String jwsPayload = removePaddingFromBase64(
        base64Url.encode(utf8.encode(json.encode(payload))));
    String jwsSignature =
        removePaddingFromBase64(base64Url.encode(signature.toList()));

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
        'protected': removePaddingFromBase64(
            base64Url.encode(utf8.encode(json.encode(header.protected)))),
        'header': header.unprotected,
        'payload': removePaddingFromBase64(
            base64Url.encode(utf8.encode(json.encode(payload)))),
        'signature':
            removePaddingFromBase64(base64Url.encode(signature.toList())),
      };

  Map<String, dynamic> jsonContent() => {
        'protected': header.protected,
        'header': header.unprotected,
        'payload': payload,
        'signature': signature,
      };

  @override
  String toString() => toJson().toString();

  bool verify(Jwk jsonWebKey) {
    try {
      Jwt.verified(this, jsonWebKey);
      return true;
    } on Exception {
      return false;
    }
  }

  Jwt verified(Jwk jsonWebKey) {
    return Jwt.verified(this, jsonWebKey);
  }
}

class KbJws extends Jws {
  KbJws({
    required super.payload,
    required super.signature,
    required super.header,
  });

  factory KbJws.fromCompactSerialization(String string) {
    Map<String, dynamic> protected = json.decode(utf8
        .decode(base64Url.decode(addPaddingToBase64(string.split('.')[0]))));
    Map<String, dynamic> payload = json.decode(utf8
        .decode(base64Url.decode(addPaddingToBase64(string.split('.')[1]))));
    Uint8List signature =
        base64Url.decode(addPaddingToBase64(string.split('.')[2]));

    return KbJws(
        payload: payload,
        signature: signature,
        header: JwsJoseHeader.fromJson({'protected': protected}));
  }

  @override
  KbJwt verified(Jwk jsonWebKey) {
    return KbJwt.verified(this, jsonWebKey);
  }
}
