import 'dart:convert';

import 'package:json_path/json_path.dart';
import 'package:sd_jwt/sd_jwt.dart';

Future<void> main() async {
  // At first, you need some key material for signing and verification tasks.
  // You can use internal data structures to handle keys:

  var issuerJwk =
      Jwk(keyType: KeyType.ec, key: EcPrivateKey.generate(Curve.p521));
  var issuerCryptoProvider =
      PointyCastleCryptoProvider(issuerJwk.key as EcPrivateKey);

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
  var holderCryptoProvider =
      PointyCastleCryptoProvider(holderJwk.key as EcPrivateKey);
  // Sign the SD-JWT and send the resulting SD-JWS to the holder

  SdJws awesomeSigned = await awesome.sign(
      signer: issuerCryptoProvider,
      signingAlgorithm: SigningAlgorithm.ecdsaSha512Prime);

  String awesomeSignedCompact = awesomeSigned.toCompactSerialization();

  // A HOLDER now can disclose some attributes and then bind his key material to
  // the SD-JWS by adding a Key Binding JWS (KB-JWS):

  awesomeSigned = SdJws.fromCompactSerialization(awesomeSignedCompact);
  print(json.encode(awesomeSigned.jsonContent()));

  var toPresent = awesomeSigned.disclose(
      [JsonPath(r'$.address.street_address'), JsonPath(r'$.given_name')]);

  String nonce = '1234567890'; // promoted by verifier
  String audience = 'https://verfifier.example.tld'; // promoted by verifier
  SdJws awesomePresentation = await toPresent.bind(
      signer: holderCryptoProvider,
      signingAlgorithm: SigningAlgorithm.ecdsaSha256Prime,
      audience: audience,
      issuedAt: DateTime.now(),
      nonce: nonce);

  String awesomePresentationCompact =
      awesomePresentation.toCompactSerialization();

  // Send the resulting SD-JWS to the verifier

  // A VERIFIER can verify the signatures of the SD-JWS. If a Key Binding
  // JWT is present, the corresponding public key can be found, e.g., in the
  // value of the `cnf` (confirmation) property of the issuer signed SD-JWS:

  awesomePresentation =
      SdJws.fromCompactSerialization(awesomePresentationCompact);

  SdJwt awesomeVerified;
  KbJwt kbJwtParsed;

  var verified = await awesomePresentation.verify(issuerCryptoProvider);
  print('Presentation: $verified');
  awesomeVerified = awesomePresentation.toSdJwt();

  try {
    var kbJwtVerified =
        awesomePresentation.keyBindingJws!.verify(holderCryptoProvider);
    print('KB-JWS: $kbJwtVerified');
    kbJwtParsed = awesomePresentation.keyBindingJws!.toKbJwt();
  } on Exception catch (e) {
    print('KB-JWS: $e');
    return;
  }

// Currently, only the signatures of both JWSs are verified. This means
// that their payloads are considered trustworthy. Next, verify if the digest
// of the `sd_hash` (sdHash) property matches the specified digest of the SD-JWS:

  print(base64.encode(awesomePresentation.digest) ==
      base64.encode(kbJwtParsed.sdHash));

  print(json.encode(awesomeVerified));
}
