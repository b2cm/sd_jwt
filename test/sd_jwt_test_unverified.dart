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

  test('simple', () {
    SdJwt sdJwt = SdJwt(
        claims: claims,
        issuer: "https://issuer.example.com",
        issuedAt: DateTime.fromMillisecondsSinceEpoch(1683000000 * 1000),
        expirationTime: DateTime.fromMillisecondsSinceEpoch(1883000000 * 1000));

    Jwk jwk = Jwk(keyType: KeyType.ec, key: EcPrivateKey.generate(Curve.p256));
    SdJws sdJws = sdJwt.sign(jsonWebKey: jwk, signingAlgorithm: SigningAlgorithm.ecdsaSha256Koblitz);
    SdJwt unverified = sdJws.unverified();

    print(json.encode(unverified));

    expect(unverified.payload['iss'], 'https://issuer.example.com');
    expect(unverified.payload['iat'], 1683000000);
    expect(unverified.payload['exp'], 1883000000);
    expect(unverified.payload['sub'], '6c5c0a49-b589-431d-bae7-219122a9ec2c');
    expect(unverified.payload['_sd_alg'], 'sha-256');

    print(json.encode(unverified.claims));

    expect(unverified.claims['address']['street_address'], 'Schulstr. 12');
    expect(unverified.claims['address']['locality'], 'Schulpforta');
    expect(unverified.claims['address']['region'], 'Sachsen-Anhalt');
    expect(unverified.claims['address']['country'], 'DE');
  });
}