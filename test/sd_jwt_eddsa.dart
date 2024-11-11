import 'package:sd_jwt/sd_jwt.dart';
import 'package:test/test.dart';

void main() {
  test('Sign and verify', () async {
    Jwk jsonWebKey = Jwk(
        keyType: KeyType.okp,
        key: EdPrivateKey.generate(curve: Curve.curve25519));
    // jsonWebKeyStore.addKey(JsonWebKey.fromJson(jsonWebKey.toJson()));
    var awesome = Jwt(additionalClaims: {'vc': 'VerifiableCredential'});
    Jws jws = await awesome.sign(
        signingAlgorithm: SigningAlgorithm.eddsa25519Sha512,
        signer: Ed25519EdwardsCryptoProvider(jsonWebKey.key as EdPrivateKey));
    print(jsonWebKey.toJson());
    print(jws.toCompactSerialization());
    print(jws.toJson());
    print(jws.jsonContent());
    expect(
        await jws.verify(
            Ed25519EdwardsCryptoProvider(jsonWebKey.key as EdPrivateKey)),
        true);
  });

  test('Export and Import', () async {
    var awesome = Jwt(additionalClaims: {'vc': 'VerifiableCredential'});
    awesome.header.type = 'test';
    awesome.header.contentType = 'test';

    var exported = awesome.toJson();
    print(exported);
    expect(exported['header']['typ'], 'test');
    expect(exported['header']['cty'], 'test');
    expect(exported['payload']['vc'], 'VerifiableCredential');
    var imported = Jwt.fromJson(exported);
    print(imported);
    expect(imported.header.type, 'test');
    expect(imported.header.contentType, 'test');
    expect(imported.payload['vc'], 'VerifiableCredential');
    expect(imported.additionalClaims?['vc'], 'VerifiableCredential');
  });
}
