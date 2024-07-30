import 'dart:convert';
import 'dart:typed_data';

import 'package:sd_jwt/src/sd_jwt_utils.dart';

class RFC7515 {
  static Uint8List verificationInput(
          {required Uint8List protectedHeader, required Uint8List payload}) =>
      ascii.encode(
          '${removePaddingFromBase64(base64Url.encode(protectedHeader))}.${removePaddingFromBase64(base64Url.encode(payload))}');

  static Uint8List signingInput(
          {required Map<String, dynamic> protectedHeader,
          required Map<String, dynamic> payload}) =>
      ascii.encode(
          '${removePaddingFromBase64(base64Url.encode(utf8.encode(json.encode(protectedHeader))))}.${removePaddingFromBase64(base64Url.encode(utf8.encode(json.encode(payload))))}');

  static Uint8List bytes(Map<String, dynamic> map) =>
      utf8.encode(json.encode(map));

}
