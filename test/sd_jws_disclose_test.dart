import 'package:json_path/json_path.dart';
import 'package:sd_jwt/sd_jwt.dart';
import 'package:test/test.dart';

void main() {
  group('Recursive SD-Jwt', () {
    var d =
        'eyJ0eXAiOiJ2YytzZC1qd3QiLCJhbGciOiJFUzI1NiJ9.eyJfc2QiOlsiNnFJS0JJZ2E2dVFLOHE2VWpkVXU2OHpUTTd3Q3N6d3NTcll1em9lTzhUcyIsIl9DREN3X2lhcXRQX1k1OThGTUhfblk1Z3k0aEFPT0JwVl9NMFVsckE2SkEiLCJoVmh1Yi13Ym5pRU5JV3gzUlZ5TFFUOUlES2t3dkhpLTF1clpOUVdONFBJIiwiVW9jaTlzLUh1S3o2MWpHbFk4VXIwc1gwUldIQkg5MjRYaFNWZy1pYnJKWSIsInhCRk1qdXgtSFA2N1Jvb3JDNGtKTkhMckNidF9EYm10TVRwOWxDbkk2NHciLCJfanB6MFptMVg4NXdRWWt0SW5DSUVDWFg2STBsTFZ6QVlYR2NXN3B4SVVnIiwiLUk5eVA1SjZlWkVFSXVJWExPakdVU1JsMV90WTJ2b1VOSE1fclotaDV0cyIsIm1hLV9NSjE2eC1oSGFxWks4dHpHT0FrRWNSamdKY0EyUlVGTzZVaTVXcTQiXSwidmN0IjoiZXUuZXVyb3BhLmVjLmV1ZGkucGlkLjEiLCJfc2RfYWxnIjoic2hhMy0yNTYiLCJpc3MiOiJodHRwczovL2lzc3Vlci1iYWNrZW5kLmV1ZGl3LmRldiIsImNuZiI6eyJqd2siOnsia3R5IjoiRUMiLCJjcnYiOiJQLTI1NiIsIngiOiJ5V0g0ajZBeVZPelpTU0FWUHNCdnFHMXowWFluV3c4VDJKUG0ydVJiOEtZIiwieSI6IjY0LTB3Qy15Vm5iMzZiaGxZVXdIV0pUaWtRaEM0UmFneG9FRW0teHBHRXMifX0sImV4cCI6MTcyNDkxODYwNCwiaWF0IjoxNzIyMzI2NjA0LCJhZ2VfZXF1YWxfb3Jfb3ZlciI6eyJfc2QiOlsieVVCWW4xMWpPSTJxbk9leTdBaU13eDNPWVdMcG5qOEZNLTVTejBzZlF2RSJdfX0.y-V7bK1b-Tuh9euRXLrLaogaKkZlksvsl8FtxcGHWfez1ENrZFQgbZU4yLX-i28GYFKio8C_enrJYTjDBU6oYA~WyI3VGdxWmV4ZVNHb3JJeUtMWHI4NTJRIiwiaXNzdWFuY2VfZGF0ZSIsIjIwMjQtMDctMzAiXQ~WyJoMThJMXIyYW5YWTNaYkdjU3lmdjJBIiwiZ2l2ZW5fbmFtZSIsIlR5bGVyIl0~WyJzZHNKVENwUUZxdGdFOGVjVmJqNDd3IiwiZmFtaWx5X25hbWUiLCJOZWFsIl0~WyJFRkZuZjB0Qk9XSzVoYndCckVBZHNRIiwiYmlydGhkYXRlIiwiMTk1NS0wNC0xMiJd~WyI2VW5TOU5GcnRkaTAybnh6bS1XeWp3IiwiMTgiLHRydWVd~WyJkNWZmVVJtZmFPQThrNngzRVBEWlJBIiwiZ2VuZGVyIiwxXQ~WyJxZnczWHowSEUwdHd4UEdPeTRySll3IiwiYWdlX2luX3llYXJzIiwxOTU1XQ~WyJPWUNoVC16UlpScGJHdkJvNTRXVExRIiwiYmlydGhkYXRlX3llYXIiLCIxOTU1Il0~WyJoVU5ycmdwelQyVTZXNWpkZ1BuYkR3IiwiY291bnRyeSIsIkFUIl0~WyI0TmlQWnlJck41ZENQbzRpMzVzaHVnIiwicmVnaW9uIiwiTG93ZXIgQXVzdHJpYSJd~WyJFdlEwSWlabFVhTjVWeDRKRUI1U21nIiwibG9jYWxpdHkiLCJHZW1laW5kZSBCaWJlcmJhY2giXQ~WyJqakNKUUxYamZsSktFVXRiMEdncGlnIiwicG9zdGFsX2NvZGUiLCIzMzMxIl0~WyJNVmtNSDBNbGxVTU55UVZSQ1VobUx3Iiwic3RyZWV0X2FkZHJlc3MiLCIxMDEgVHJhdW5lciJd~WyJWelY4bUxVbmFSWmZBdWkwYVd6eEVBIiwiYWRkcmVzcyIseyJfc2QiOlsic3RGaFhuLXd1YW9sQnhVeEpCMHp1Yk1UZDZMcFNTSDhlc3NhQ25jUmo4VSIsImw0Y1NyX2t6Qk55ZHJqUlRaYTY2M1o5MFVoeWFDb3hEVzUya0M2Z0ZsN2siLCJ2Z2U5dUFySGdTR2M3TkljR2V2T1dXSkk5MnJIV0dramFEZXE4S2NwWjJvIiwiOERHRVprU2phX0FCdHk5QWhtXzlQd29ZbmdFSkl0TkNmZ1Q5bWdISVl3YyIsIjM3TksxWTl0Sl9UQUdMODllb1hSaFZ2QjRGdkxCNGJxQlRQalJ4UFlucVkiXX1d~';
    var sdJws = SdJws.fromCompactSerialization(d);

    test('disclose toplevel attribute', () {
      var disclosed = sdJws.disclose([JsonPath(r'$.birthdate')]);

      expect(disclosed.disclosures!.length, 1);

      var sdJwt = disclosed.toSdJwt();

      expect(sdJwt.claims.containsKey('birthdate'), isTrue);
    });

    test('disclose attribute from nested object', () {
      var disclosed = sdJws.disclose([JsonPath(r'$.address.street_address')]);

      expect(disclosed.disclosures!.length, 2);

      var sdJwt = disclosed.toSdJwt();

      expect(sdJwt.claims.containsKey('address'), isTrue);
      Map address = sdJwt.claims['address'];

      expect(address.containsKey('street_address'), isTrue);
    });

    test('disclose nested object', () {
      var disclosed = sdJws.disclose([JsonPath(r'$.address')]);

      expect(disclosed.disclosures!.length, 6);

      var sdJwt = disclosed.toSdJwt();

      expect(sdJwt.claims.containsKey('address'), isTrue);
      Map address = sdJwt.claims['address'];

      expect(address.containsKey('street_address'), isTrue);
      expect(address.containsKey('postal_code'), isTrue);
      expect(address.containsKey('locality'), isTrue);
      expect(address.containsKey('region'), isTrue);
      expect(address.containsKey('country'), isTrue);
    });
  });

  group('Structured sd jwt', () {
    var d =
        'eyJhbGciOiJFUzI1NiJ9.eyJhZGRyZXNzIjp7ImNvdW50cnkiOlt7Ii4uLiI6InZuNFlySVI3eUd4NUFqUUY4WkllMFdkSzlUMzJrSmU4TUlzVmhYaVF6T2sifSx7Ii4uLiI6IjhONkJDWlpITVVlcGlCUXlfWDFfX2ppcXZMbDkxOU8tZzdUZ3RKVjdmUm8ifV0sIl9zZCI6WyJ4MFpydGp5ZF9tX0x1c3ZwaU5xQTBaaVZLVHN2UTJSMkNIQ21mMXAwendnIiwiWURXblRfSGhvQzNiSGgtYTh3RGJLQi1mdUtZRGdmTzVpRm1PT0dvY0FNdyIsIl92ZWZaMlVfcnJGZ1BZYnRXZlotX2w1cVI0Z3E5T3czcWZWQ1g3VnA4U0kiXX0sInNvbWVDbGFpbSI6InNvbWVWYWx1ZSIsIl9zZCI6WyJkYUxqNkxCdkpjN29zWlJ3Z0dsc3dhUTJtVHhLZzIxRzlVbmlRQ2F5Q3ZnIl0sImlzcyI6Imh0dHBzOi8vZG9tYWluLnRsZC9pc3N1ZXIiLCJzdWIiOiI2YzVjMGE0OS1iNTg5LTQzMWQtYmFlNy0yMTkxMjJhOWVjMmMiLCJpYXQiOjE3MTUzOTEzMzQsIl9zZF9hbGciOiJzaGEtMjU2IiwiY25mIjp7Imp3ayI6eyJrdHkiOiJFQyIsIngiOiJfbElacHZuYVA0d2xBZU1sWHRqS0QyV3dkYUFocGpkbzFxZWIydlNfcktnIiwieSI6IjBpR19pWEdzN1g2LU1HNXoxR0JTZE5RcG5qTHA0MHlUb1dHSlAweW1xZVEiLCJjcnYiOiJQLTI1NiJ9fX0.BmVdXxtKLsnheTX1gKb29EGuvApzf2JZDPkbWI-Nl3zmlx2vLGpC8av4v8hGmXMtJisY8Ob4OtjsUtWU2rH9Nw~WyI0OUVYbGVScG1CTXA4dFBjSldlYUtOaUlLVTE2eWlZRGc3M0h0Qm9ZRjFvIiwgImdpdmVuX25hbWUiLCAiSm9obiJd~WyJ4OFVuVzJsemJOd0NZVGMtNTJ5UWpwSTBOcmtOdEEwbFRraUdlM0ROMURZIiwgInN0cmVldF9hZGRyZXNzIiwgIlNjaHVsc3RyLiAxMiJd~WyJ2Vkg5RUs2UTAtMnZXN0R0VGU0cjIwZkZQaUxHMVRneDdvQVgzc0RrTElZIiwgImxvY2FsaXR5IiwgIlNjaHVscGZvcnRhIl0~WyJmLTdFcVJFcDBBTTF0NG1MekZLWmdSa1NBZExOLWpqSkhXM19WajdOSS0wIiwgInJlZ2lvbiIsICJTYWNoc2VuLUFuaGFsdCJd~WyJheklSbFE4eUVTRWJHYmJvQTNnc0FYcEszZUdCWHJMWEJlZlBHdDh3Rnc0IiwgIkRFIl0~WyIyMFEwUXd6cThEbU1JUVRYLTI2dnVTSk9KRGs5THFxQmptMklJbURINWE4IiwgIkVOIl0~';
    var sdJws = SdJws.fromCompactSerialization(d);
    test('disclose toplevel attribute', () {
      var disclosed = sdJws.disclose([JsonPath(r'$.given_name')]);

      expect(disclosed.disclosures!.length, 1);

      var sdJwt = disclosed.toSdJwt();

      expect(sdJwt.claims.containsKey('given_name'), isTrue);
    });

    test('disclose attribute from nested object', () {
      var disclosed = sdJws.disclose([JsonPath(r'$.address.street_address')]);

      expect(disclosed.disclosures!.length, 1);

      var sdJwt = disclosed.toSdJwt();

      expect(sdJwt.claims.containsKey('address'), isTrue);
      Map address = sdJwt.claims['address'];

      expect(address.containsKey('street_address'), isTrue);
    });

    test('disclose nested object with list inside', () {
      var disclosed = sdJws.disclose([JsonPath(r'$.address')]);

      expect(disclosed.disclosures!.length, 5);

      var sdJwt = disclosed.toSdJwt();

      expect(sdJwt.claims.containsKey('address'), isTrue);
      Map address = sdJwt.claims['address'];

      expect(address.containsKey('street_address'), isTrue);
      expect(address.containsKey('locality'), isTrue);
      expect(address.containsKey('region'), isTrue);
      expect(address.containsKey('country'), isTrue);

      List country = address['country'];
      expect(country.length, 2);
    });

    test('disclose one value from a List', () {
      var disclosed = sdJws.disclose([JsonPath(r'$.address.country[0]')]);

      expect(disclosed.disclosures!.length, 1);

      var sdJwt = disclosed.toSdJwt();

      expect(sdJwt.claims.containsKey('address'), isTrue);
      Map address = sdJwt.claims['address'];

      expect(address.containsKey('country'), isTrue);

      List country = address['country'];
      expect(country.length, 1);
    });
  });
}
