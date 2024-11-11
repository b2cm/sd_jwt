import 'dart:convert';

import 'package:sd_jwt/sd_jwt.dart';
import 'package:test/test.dart';

void main() {
  Map<String, dynamic> claims = {
    "sub": "6c5c0a49-b589-431d-bae7-219122a9ec2c",
    "address": {
      "street_address": "Schulstr. 12",
      "locality": "Schulpforta",
      "region": "Sachsen-Anhalt",
      "country": "DE"
    }
  };

  test('simple', () async {
    SdJwt sdJwt = SdJwt(
        claims: claims,
        issuer: "https://issuer.example.com",
        issuedAt: DateTime.fromMillisecondsSinceEpoch(1683000000 * 1000),
        expirationTime: DateTime.fromMillisecondsSinceEpoch(1883000000 * 1000));

    Jwk jwk = Jwk(keyType: KeyType.ec, key: EcPrivateKey.generate(Curve.p256));
    SdJws sdJws = await sdJwt.sign(
        signer: PointyCastleCryptoProvider(jwk.key as EcPrivateKey),
        signingAlgorithm: SigningAlgorithm.ecdsaSha256Koblitz);
    SdJwt unverified = sdJws.toSdJwt();

    print(json.encode(unverified));

    expect(unverified.payload['iss'], 'https://issuer.example.com');
    expect(unverified.payload['iat'], 1683000000);
    expect(unverified.payload['exp'], 1883000000);
    expect(unverified.payload['sub'], '6c5c0a49-b589-431d-bae7-219122a9ec2c');
    expect(unverified.payload['_sd_alg'], 'sha-256');

    print(json.encode(unverified.additionalClaims));

    expect(unverified.additionalClaims?['address']['street_address'],
        'Schulstr. 12');
    expect(unverified.additionalClaims?['address']['locality'], 'Schulpforta');
    expect(unverified.additionalClaims?['address']['region'], 'Sachsen-Anhalt');
    expect(unverified.additionalClaims?['address']['country'], 'DE');
  });
}
