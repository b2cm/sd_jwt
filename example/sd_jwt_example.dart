import 'dart:convert';

import 'package:sd_jwt/sd_jwt.dart';
import 'package:sd_jwt/src/sd_jwt_crypto_provider.dart';
import 'package:sd_jwt/src/sd_jwt_jwk.dart';
import 'package:sd_jwt/src/sd_jwt_jws.dart';

Future<void> main() async {
  // At first, you need some key material for signing and verification tasks.
  // If you want to use an external key management system, simply
  // export and import a JSON Web Key from yours to this:

  Map<String, dynamic> extJwk = {'kty': 'dummy'};
  Jwk issuerJwk;
  try {
    issuerJwk = Jwk.fromJson(extJwk);
  } on Exception catch (e) {
    print(e); // Exception: Key type `dummy` not supported.
  }

  // Otherwise, you can use internal data structures to handle keys:

  issuerJwk = Jwk(keyType: KeyType.ec, key: EcPrivateKey.generate(Curve.p256));

  // Now, let's create a SD-JWT. Registered claims names by RFC 7519 are parsed
  // and removed from claims set or can be set directly:

  var awesome = SdJwt(
    claims: {
      'given_name': 'John',
      "sub": "6c5c0a49-b589-431d-bae7-219122a9ec2c",
      "iss": 'https://domain.tld/issuer',
      "iat": 1715391334,
      "address": {
        "street_address": "Schulstr. 12",
        "locality": "Schulpforta",
        "region": "Sachsen-Anhalt",
        "country": ["DE", "EN"],
      }
    },
  );

  // Or

  awesome = SdJwt(
    subject: "6c5c0a49-b589-431d-bae7-219122a9ec2c",
    issuer: 'https://domain.tld/issuer',
    issuedAt: DateTime.fromMillisecondsSinceEpoch(1715391334 * 1000),
    claims: {
      'given_name': 'John',
      "address": {
        "street_address": "Schulstr. 12",
        "locality": "Schulpforta",
        "region": "Sachsen-Anhalt",
        "country": ["DE", "EN"],
      }
    },
  );

  // By default, all claims except registered will be recursively undisclosed.
  // If you need some additional claims that are always disclosed, you can set
  // this in the constructor or at a later point:

  awesome.alwaysDisclosed = {
    'someClaim': 'someValue',
  };

  // Optionally include a public key of the intended holder:

  Jwk holderJwk =
      Jwk(keyType: KeyType.ec, key: EcPrivateKey.generate(Curve.p256));
  awesome.confirmation = JwkConfirmation(holderJwk.public);

  // Sign the SD-JWT and send the resulting SD-JWS to the holder

  SdJws awesomeSigned = awesome.sign(
      jsonWebKey: issuerJwk, signingAlgorithm: SigningAlgorithm.ecdsaSha256Prime);

  String awesomeSignedCompact = awesomeSigned.toCompactSerialization();


  // A HOLDER now can remove some Disclosures and then bind his key material to
  // the SD-JWS by adding a Key Binding JWS (KB-JWS):

  awesomeSigned = SdJws.fromCompactSerialization(awesomeSignedCompact);
  print(json.encode(awesomeSigned.jsonContent()));

  Disclosure toRemove = awesomeSigned.disclosures!.singleWhere((e) => e.key == 'street_address');
  awesomeSigned.disclosures!.remove(toRemove);
  // awesomeSigned.disclosures!.clear();

  String nonce = '1234567890'; // promoted by verifier
  String audience = 'https://verfifier.example.tld'; // promoted by verifier
  SdJws awesomePresentation = awesomeSigned.bind(
      jsonWebKey: holderJwk,
      signingAlgorithm: SigningAlgorithm.ecdsaSha256Prime,
      audience: audience,
      issuedAt: DateTime.now(),
      nonce: nonce);

  String awesomePresentationCompact = awesomePresentation.toCompactSerialization();

  // Send the resulting SD-JWS to the verifier

  // A VERIFIER can verify the signatures of the SD-JWS. If a Key Binding
  // JWT is present, the corresponding public key can be found, e.g., in the
  // value of the `cnf` (confirmation) property of the issuer signed SD-JWS:

  awesomePresentation = SdJws.fromCompactSerialization(awesomePresentationCompact);

  SdJwt awesomeVerified;
  KbJwt kbJwtVerified;
  try {
    awesomeVerified = awesomePresentation.verified(issuerJwk.public);
  } on Exception catch (e) {
    print('SD-JWS: $e');
    return;
  }

  try {
    kbJwtVerified = awesomePresentation.keyBindingJws!
        .verified((awesomeVerified.confirmation as JwkConfirmation).jwk.public);
  } on Exception catch (e) {
    print('KB-JWS: $e');
    return;
  }


// Currently, only the signatures of both JWSs are verified. This means
// that their payloads are considered trustworthy. Next, verify if the digest
// of the `sd_hash` (sdHash) property matches the specified digest of the SD-JWS:

  print(base64.encode(awesomePresentation.digest) ==
      base64.encode(kbJwtVerified.sdHash));

  print(json.encode(awesomeVerified));

}
