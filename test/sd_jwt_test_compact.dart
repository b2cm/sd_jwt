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

  test('tildes', () {
    SdJwt sdJwt = SdJwt(
        claims: claims,
        issuer: "https://issuer.example.com",
        issuedAt: DateTime.fromMillisecondsSinceEpoch(1683000000 * 1000),
        expirationTime: DateTime.fromMillisecondsSinceEpoch(1883000000 * 1000));

    Jwk jwk = Jwk(keyType: KeyType.ec, key: EcPrivateKey.generate(Curve.p256));
    SdJws sdJws = sdJwt.sign(
        jsonWebKey: jwk, signingAlgorithm: SigningAlgorithm.ecdsaSha256Koblitz);
    String compact = sdJws.toCompactSerialization();
    print(compact);

    SdJws sdJwsFromCompact = SdJws.fromCompactSerialization(compact);

    sdJwsFromCompact.bind(
        jsonWebKey: jwk,
        audience: 'audience',
        issuedAt: DateTime.now(),
        nonce: 'nonce',
        signingAlgorithm: SigningAlgorithm.ecdsaSha256Koblitz);

    compact = sdJwsFromCompact.toCompactSerialization();
    print(compact);
    sdJwsFromCompact = SdJws.fromCompactSerialization(compact);
    print(sdJwsFromCompact);

    expect(sdJwsFromCompact.keyBindingJws, isNotNull);
  });
}
