import 'dart:typed_data';

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