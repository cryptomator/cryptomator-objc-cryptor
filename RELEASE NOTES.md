# Release Notes

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
