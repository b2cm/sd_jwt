import 'dart:math';
import 'dart:typed_data';

import 'package:pointycastle/export.dart' as pointy_castle;
import 'package:sd_jwt/sd_jwt.dart';

String addPaddingToBase64(String base64Input) {
  while (base64Input.length % 4 != 0) {
    base64Input += '=';
  }
  return base64Input;
}

String removePaddingFromBase64(String base64Input) {
  while (base64Input.endsWith('=')) {
    base64Input = base64Input.substring(0, base64Input.length - 1);
  }
  return base64Input;
}

Uint8List bigIntToUInt8List(BigInt bigInt) {
  int length = bigInt.bitLength;
  Uint8List bytes = Uint8List((length / 8).ceil());
  for (int i = 0; i < bytes.length; i++) {
    bytes[i] = (bigInt >> (i * 8)).toUnsigned(8).toInt();
  }
  return Uint8List.fromList(bytes.reversed.toList());
}

BigInt uInt8ListToBigInt(Uint8List bytes) {
  BigInt result = BigInt.from(0);
  for (int i = 0; i < bytes.length; i++) {
    result += BigInt.from(bytes[bytes.length - i - 1]) << (8 * i);
  }
  return result;
}

final _b256 = BigInt.from(256);

Iterable<int> bigIntToBytes(BigInt v, int length) sync* {
  for (var i = 0; i < length; i++) {
    yield (v % _b256).toInt();
    v = v ~/ _b256;
  }
}

BigInt bigIntFromBytes(Iterable<int> bytes) {
  return bytes.fold(BigInt.zero, (a, b) => a * _b256 + BigInt.from(b));
}

pointy_castle.Digest getDigest(SigningAlgorithm algorithm) {
  switch (algorithm) {
    case SigningAlgorithm.ecdsaSha256Prime:
      return pointy_castle.SHA256Digest();
    case SigningAlgorithm.ecdsaSha256Koblitz:
      return pointy_castle.SHA256Digest();
    case SigningAlgorithm.ecdsaSha384Prime:
      return pointy_castle.SHA384Digest();
    case SigningAlgorithm.ecdsaSha512Prime:
      return pointy_castle.SHA512Digest();
    case SigningAlgorithm.ecdsaSha256KoblitzRecovery:
      return pointy_castle.SHA256Digest();
    default:
      throw Exception(
          'Signing algorithm not supported by this implementation.');
  }
}

@override
Uint8List generateDigest(
    {required Uint8List data, required DigestAlgorithm algorithm}) {
  pointy_castle.Digest digest;
  switch (algorithm) {
    case DigestAlgorithm.sha2_256:
      digest = pointy_castle.SHA256Digest();
    case DigestAlgorithm.sha2_384:
      digest = pointy_castle.SHA384Digest();
    case DigestAlgorithm.sha2_512:
      digest = pointy_castle.SHA512Digest();
    case DigestAlgorithm.sha3_256:
      digest = pointy_castle.SHA3Digest(256);
  }
  return digest.process(data);
}

class DefaultSecureRandom implements pointy_castle.SecureRandom {
  final Random random = Random.secure();

  @override
  String get algorithmName => 'dart.math.Random.secure()';

  @override
  BigInt nextBigInteger(int bitLength) {
    return BigInt.parse(
        Iterable.generate(bitLength, (_) => random.nextBool() ? '1' : '0')
            .join(''),
        radix: 2);
  }

  @override
  Uint8List nextBytes(int count) =>
      Uint8List.fromList(List.generate(count, (_) => nextUint8()));

  @override
  int nextUint16() => random.nextInt(256 * 256);

  @override
  int nextUint32() => random.nextInt(256 * 256 * 256 * 256);

  @override
  int nextUint8() => random.nextInt(256);

  @override
  void seed(pointy_castle.CipherParameters params) {
    throw UnsupportedError('Seed not supported for this SecureRandom');
  }
}
