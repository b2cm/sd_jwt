# sd_jwt
This package contains a pure dart implementation of the IETF draft 
[Selective Disclosure for JWTs (SD-JWT)](https://datatracker.ietf.org/doc/draft-ietf-oauth-selective-disclosure-jwt/).
Beside this it is also useful for handling JWT and JWS.

## Usage
### SD-JWT
To generate an basic SD-JWT and sign it you can use
```
var sdJwt = SdJwt(
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
var issuerJwk =
     Jwk(keyType: KeyType.ec, key: EcPrivateKey.generate(Curve.p521));
var issuerCryptoProvider =
     PointyCastleCryptoProvider(issuerJwk.key as EcPrivateKey);
SdJws signed = await sdJwt.sign(signer: issuerCryptoProvider,signingAlgorithm: SigningAlgorithm.ecdsaSha512Prime);
```

For a more complex example please consult [this](./example/sd_jwt_example.dart).

### JWT
To generate a JWT you can use the following

```
var jwt =
     sd_jwt.Jwt(additionalClaims: payload, issuedAt: DateTime.now());
var jws = await jwt.sign(
     signer: issuerCryptoProvider,
     header: sd_jwt.JwsJoseHeader(
         algorithm: sd_jwt.SigningAlgorithm.ecdsaSha512Prime,
         jsonWebKey: issuerJwk));
```
For verification of this JWT use
```
var verified = await jws.verify(PointyCastleCryptoProvider(issuerJwk.key as EcPublicKey));
```