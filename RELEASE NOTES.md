# Release Notes

## Version 1.5.2

- Simplified `-[NSData seto_base64urlEncodedString]` method.

## Version 1.5.1

- Added `NSData+SETOBase64urlEncoding` to public header files.

## Version 1.5.0

Filenames are encoded with base64url so that name shortenings are less likely. The ciphertext file layout has been redesigned.

- Added vault version 7 compatibility.

## Version 1.4.3

- Fixed breaking change introduced in 1.4.2

## Version 1.4.2

- Fixed crash when trying to decrypt filename with invalid ciphertext

## Version 1.4.1

- Updated KZPropertyMapper to version ~> 2.9.0 in Podspec.

## Version 1.4.0

- Increased default scrypt cost param to 32768.
- Updated scrypt to version 1.2.1.
- Updated KZPropertyMapper to version ~> 2.9.0.

## Version 1.3.3

- Fixed crash in `SETOMasterKey`, `updateFromJSONData:` method needed to handle nil data.

## Version 1.3.2

- Fixed crash in `SETOAsyncCryptor`, `masterKeyWithPassword:pepper:` method had to be decorated.

## Version 1.3.1

- Added support for application-specific peppers.

## Version 1.3.0

Unicode is hard. The password is now normalized in NFC.

- Added vault version 6 compatibility.

## Version 1.2.3

- Fixed version MAC calculation.

## Version 1.2.2

- Fixed crash in `SETOAsyncCryptor`, `cleartextChunkSize` and `ciphertextChunkSize` methods are now decorated.

## Version 1.2.1

- Exposed `SETOCryptorVersion` as a public enum.

## Version 1.2.0

We've decided to disable file size obfuscation. File sizes can be determined in O(1) instead of having to read and decrypt the file header. This allows showing file sizes in the directory listing without having to download each file first.

- Added vault version 5 compatibility.
- Added `+[SETOCryptorProvider cleartextSizeFromCiphertextSize:withCryptor:]` and `+[SETOCryptorProvider ciphertextSizeFromCleartextSize:withCryptor:]` methods for version 5 cryptors.

## Version 1.1.4

- `SETOCryptor` version is now an accessible property.

## Version 1.1.3

- Fixed crash in `SETOAsyncCryptor`, dispatch queue property has to be defined as `strong`.

## Version 1.1.2

- Removed assertions in `SETOCryptor` initialization for `SETOAsyncCryptor` decorator to work.

## Version 1.1.1

- Fixed typo, `SETOCryptorProviderError` enum was wrongly named.

## Version 1.1.0

Updated the API and usage significantly. This framework has been tuned to support multiple vault formats. Versions `3` and `4` are cryptographically identical, however these changes are still necessary, because the versions do not only represent a cryptographic version.

- Added `SETOCryptorProvider` as a factory for `SETOCryptor` objects. From now on, do not create cryptor instances directly, but use this factory instead.
- Added `SETOCryptorV3` with the former `SETOCryptomatorCryptor` implementation.
- Renamed `SETOCryptomatorCryptor` class to `SETOCryptor`.
- `SETOCryptor` is now an abstract class.
- Renamed `SETOAsyncCryptomatorCryptor` class to `SETOAsyncCryptor`.
- `SETOAsyncCryptor` is now using a serial queue (utility QoS class) as default.

## Version 1.0.2

- Reverted filename normalization, because it's cryptographically irrelevant.

## Version 1.0.1

- Normalized filename using Unicode Normalization Form C.
- Added version MAC to allow future versions to prevent downgrade attacks.

## Version 1.0.0

- Initial release.
