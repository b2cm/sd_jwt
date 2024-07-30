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

  test('create', () {
    SdJwt sdJwt = SdJwt(
        claims: claims,
        issuer: "https://issuer.example.com",
        issuedAt: DateTime.fromMillisecondsSinceEpoch(1683000000 * 1000),
        expirationTime: DateTime.fromMillisecondsSinceEpoch(1883000000 * 1000));
    (sdJwt.disclosures['address']['street_address'] as Disclosure).salt = '2GLC42sKQveCfGfryNRN9w';
    (sdJwt.disclosures['address']['locality'] as Disclosure).salt = 'eluV5Og3gSNII8EYnsxA_A';
    (sdJwt.disclosures['address']['region'] as Disclosure).salt = '6Ij7tM-a5iVPGboS5tmvVA';
    (sdJwt.disclosures['address']['country'] as Disclosure).salt = 'eI8ZWm9QnKPpNPeNenHdhQ';

    print(json.encode(sdJwt));

    expect(sdJwt.payload['address']['_sd'], contains('9gjVuXtdFROCgRrtNcGUXmF65rdezi_6Er_j76kmYyM'));
    expect(sdJwt.payload['address']['_sd'], contains('6vh9bq-zS4GKM_7GpggVbYzzu6oOGXrmNVGPHP75Ud0'));
    expect(sdJwt.payload['address']['_sd'], contains('KURDPh4ZC19-3tiz-Df39V8eidy1oV3a3H1Da2N0g88'));
    expect(sdJwt.payload['address']['_sd'], contains('WN9r9dCBJ8HTCsS2jKASxTjEyW5m5x65_Z_2ro2jfXM'));
    expect(sdJwt.payload['iss'], 'https://issuer.example.com');
    expect(sdJwt.payload['iat'], 1683000000);
    expect(sdJwt.payload['exp'], 1883000000);
    expect(sdJwt.payload['sub'], '6c5c0a49-b589-431d-bae7-219122a9ec2c');
    expect(sdJwt.payload['_sd_alg'], 'sha-256');
  });

  test('create and verify', () {
    SdJwt sdJwt = SdJwt(
        claims: claims,
        issuer: "https://issuer.example.com",
        issuedAt: DateTime.fromMillisecondsSinceEpoch(1683000000 * 1000),
        expirationTime: DateTime.fromMillisecondsSinceEpoch(1883000000 * 1000));
    (sdJwt.disclosures['address']['street_address'] as Disclosure).salt = '2GLC42sKQveCfGfryNRN9w';
    (sdJwt.disclosures['address']['locality'] as Disclosure).salt = 'eluV5Og3gSNII8EYnsxA_A';
    (sdJwt.disclosures['address']['region'] as Disclosure).salt = '6Ij7tM-a5iVPGboS5tmvVA';
    (sdJwt.disclosures['address']['country'] as Disclosure).salt = 'eI8ZWm9QnKPpNPeNenHdhQ';

    Jwk jwk = Jwk(keyType: KeyType.ec, key: EcPrivateKey.generate(Curve.p256));
    SdJws sdJws = sdJwt.sign(jsonWebKey: jwk, signingAlgorithm: SigningAlgorithm.ecdsaSha256Koblitz);
    SdJwt verified = sdJws.verified(jwk);

    print(json.encode(verified));

    expect(verified.payload['address']['_sd'], contains('9gjVuXtdFROCgRrtNcGUXmF65rdezi_6Er_j76kmYyM'));
    expect(verified.payload['address']['_sd'], contains('6vh9bq-zS4GKM_7GpggVbYzzu6oOGXrmNVGPHP75Ud0'));
    expect(verified.payload['address']['_sd'], contains('KURDPh4ZC19-3tiz-Df39V8eidy1oV3a3H1Da2N0g88'));
    expect(verified.payload['address']['_sd'], contains('WN9r9dCBJ8HTCsS2jKASxTjEyW5m5x65_Z_2ro2jfXM'));
    expect(verified.payload['iss'], 'https://issuer.example.com');
    expect(verified.payload['iat'], 1683000000);
    expect(verified.payload['exp'], 1883000000);
    expect(verified.payload['sub'], '6c5c0a49-b589-431d-bae7-219122a9ec2c');
    expect(verified.payload['_sd_alg'], 'sha-256');
  });

  test('create, send/receive and verify', () {
    SdJwt sdJwt = SdJwt(
        claims: claims,
        issuer: "https://issuer.example.com",
        issuedAt: DateTime.fromMillisecondsSinceEpoch(1683000000 * 1000),
        expirationTime: DateTime.fromMillisecondsSinceEpoch(1883000000 * 1000));
    (sdJwt.disclosures['address']['street_address'] as Disclosure).salt = '2GLC42sKQveCfGfryNRN9w';
    (sdJwt.disclosures['address']['locality'] as Disclosure).salt = 'eluV5Og3gSNII8EYnsxA_A';
    (sdJwt.disclosures['address']['region'] as Disclosure).salt = '6Ij7tM-a5iVPGboS5tmvVA';
    (sdJwt.disclosures['address']['country'] as Disclosure).salt = 'eI8ZWm9QnKPpNPeNenHdhQ';

    Jwk jwk = Jwk(keyType: KeyType.ec, key: EcPrivateKey.generate(Curve.p256));
    SdJws sdJws = sdJwt.sign(jsonWebKey: jwk, signingAlgorithm: SigningAlgorithm.ecdsaSha256Koblitz);
    String compactJws = sdJws.toCompactSerialization();

    SdJws jwsFromCompact = SdJws.fromCompactSerialization(compactJws);
    SdJwt verified = jwsFromCompact.verified(jwk);

    print(json.encode(verified));

    expect(verified.payload['address']['_sd'], contains('9gjVuXtdFROCgRrtNcGUXmF65rdezi_6Er_j76kmYyM'));
    expect(verified.payload['address']['_sd'], contains('6vh9bq-zS4GKM_7GpggVbYzzu6oOGXrmNVGPHP75Ud0'));
    expect(verified.payload['address']['_sd'], contains('KURDPh4ZC19-3tiz-Df39V8eidy1oV3a3H1Da2N0g88'));
    expect(verified.payload['address']['_sd'], contains('WN9r9dCBJ8HTCsS2jKASxTjEyW5m5x65_Z_2ro2jfXM'));
    expect(verified.payload['iss'], 'https://issuer.example.com');
    expect(verified.payload['iat'], 1683000000);
    expect(verified.payload['exp'], 1883000000);
    expect(verified.payload['sub'], '6c5c0a49-b589-431d-bae7-219122a9ec2c');
    expect(verified.payload['_sd_alg'], 'sha-256');
  });
}
