![SETOCryptomatorCryptor](SETOCryptomatorCryptor.png)

[![Cocoapods Compatible](https://img.shields.io/cocoapods/v/SETOCryptomatorCryptor.svg)](https://img.shields.io/cocoapods/v/SETOCryptomatorCryptor.svg)
[![Platform](https://img.shields.io/cocoapods/p/SETOCryptomatorCryptor.svg?style=flat)](http://cocoadocs.org/docsets/SETOCryptomatorCryptor)
[![Twitter](https://img.shields.io/badge/twitter-@Cryptomator-blue.svg?style=flat)](http://twitter.com/Cryptomator)

SETOCryptomatorCryptor is an iOS crypto library to access Cryptomator vaults. For more information on the security details visit [cryptomator.org](https://cryptomator.org/architecture/).

## Requirements

* iOS 8.0 or higher
* ARC enabled

## Installation

The easiest way to use SETOCryptomatorCryptor in your app is via [CocoaPods](http://cocoapods.org/ "CocoaPods").

1. Add the following line in the project's Podfile file: `pod 'SETOCryptomatorCryptor', '~> 1.4.0'`
2. Run the command `pod install` from the Podfile folder directory.

## Audits

- [Version 1.3.0 audit by Cure53](https://cryptomator.org/audits/2017-11-27%20crypto%20cure53.pdf)

| Finding | Comment |
|---|---|
| 1u1-22-001 | This issue is related to [cryptolib](https://github.com/cryptomator/cryptolib/), [cryptofs](https://github.com/cryptomator/cryptofs/), and [siv-mode](https://github.com/cryptomator/siv-mode/). |
| 1u1-22-002 | This issue is related to [siv-mode](https://github.com/cryptomator/siv-mode/). |

## Usage

### SETOCryptorProvider

`SETOCryptorProvider` is a factory for `SETOCryptor` objects. Always use the factory for creating `SETOCryptor` instances.

#### Create New Cryptor & Master Key

```objective-c
NSString *password = ...;
SETOCryptor *cryptor = [SETOCryptorProvider newCryptor];
SETOMasterKey *masterKey = [cryptor masterKeyWithPassword:password];
```

Actually, you should call these methods from a background thread, as random number generation will benefit from UI interaction.

```objective-c
NSString *password = ...;
dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
  SETOCryptor *cryptor = [SETOCryptorProvider newCryptor];
  SETOMasterKey *masterKey = [cryptor masterKeyWithPassword:password];
  dispatch_async(dispatch_get_main_queue(), ^{
    // do the rest here
  });
});
```

#### Create Cryptor From Existing Master Key

This is equivalent to an unlock attempt.

```objective-c
SETOMasterKey *masterKey = ...;
NSError *error;
SETOCryptor *cryptor = [SETOCryptorProvider cryptorFromMasterKey:masterKey withPassword:password error:&error];
if (error) {
  NSLog(@"Unlock Error: %@", error);
} else {
  NSLog(@"Unlock Success");
}
```

#### Determine File Sizes

Beginning with vault version 5, you can determine the cleartext and ciphertext sizes in O(1). Reading out the file sizes before vault version 5 is theoretically possible, but not supported by this library.

```objective-c
SETOCryptor *cryptor = ...;
NSUInteger ciphertextSize = ...;
NSUInteger cleartextSize = [SETOCryptorProvider cleartextSizeFromCiphertextSize:ciphertextSize withCryptor:cryptor];
// and the other way round with +[SETOCryptorProvider ciphertextSizeFromCleartextSize:withCryptor:]
```

### SETOCryptor

`SETOCryptor` is the core class for cryptographic operations on Cryptomator vaults. This is an abstract class, so you should use `SETOCryptorProvider` to create a `SETOCryptor` instance.

#### Directory ID Encryption

```objective-c
SETOCryptor *cryptor = ...;
NSString *directoryId = ...;
NSString *encryptedDirectoryId = [cryptor encryptDirectoryId:directoryId];
```

#### Filename Encryption and Decryption

```objective-c
SETOCryptor *cryptor = ...;
NSString *filename = ...;
NSString *directoryId = ...;
NSString *encryptedFilename = [cryptor encryptFilename:filename insideDirectoryWithId:directoryId];
NSString *decryptedFilename = [cryptor decryptFilename:encryptedFilename insideDirectoryWithId:directoryId];
```

#### File Content Authentication

```objective-c
SETOCryptor *cryptor = ...;
NSString *ciphertextFilePath = ...;
[cryptor authenticateFileAtPath:ciphertextFilePath callback:^(NSError *error) {
  if (error) {
    NSLog(@"Authentication Error: %@", error);
  } else {
    NSLog(@"Authentication Success");
  }
} progress:^(CGFloat progress) {
  NSLog(@"Authentication Progress: %.2f", progress);
}];
```

#### File Content Encryption

```objective-c
SETOCryptor *cryptor = ...;
NSString *cleartextFilePath = ...;
NSString *ciphertextFilePath = ...;
[cryptor encryptFileAtPath:cleartextFilePath toPath:ciphertextFilePath callback:^(NSError *error) {
  if (error) {
    NSLog(@"Encryption Error: %@", error);
  } else {
    NSLog(@"Encryption Success");
  }
} progress:^(CGFloat progress) {
  NSLog(@"Encryption Progress: %.2f", progress);
}];
```

#### File Content Decryption

```objective-c
SETOCryptor *cryptor = ...;
NSString *ciphertextFilePath = ...;
NSString *cleartextFilePath = ...;
[cryptor decryptFileAtPath:ciphertextFilePath toPath:cleartextFilePath callback:^(NSError *error) {
  if (error) {
    NSLog(@"Decryption Error: %@", error);
  } else {
    NSLog(@"Decryption Success");
  }
} progress:^(CGFloat progress) {
  NSLog(@"Decryption Progress: %.2f", progress);
}];
```

### SETOAsyncCryptor

`SETOAsyncCryptor` is a `SETOCryptor` decorator for running file content encryption and decryption operations asynchronously. It's useful for cryptographic operations on large files without blocking the main thread.

Create and initialize `SETOAsyncCryptor` using `initWithCryptor:queue:` to specify a dispatch queue. If you're initializing with the convenience initializer `initWithCryptor:`, a serial queue (utility QoS class) will be created and used.

### SETOMasterKey

`SETOMasterKey` holds the information necessary for the master key. All properties are immutable to prevent accidental changes. Use `updateFromJsonData:` or `updateFromDictionary:` to modify the properties in bulk. Use the convenience method `dictionaryRepresentation`, e.g. for persisting the master key.

## Contributing to Cryptomator

Please read our [contribution guide](https://github.com/cryptomator/cryptomator-objc-cryptor/blob/master/CONTRIBUTING.md), if you would like to report a bug, ask a question or help us with coding.

## Code of Conduct

Help us keep Cryptomator open and inclusive. Please read and follow our [Code of Conduct](https://github.com/cryptomator/cryptomator-objc-cryptor/blob/master/CODE_OF_CONDUCT.md).

## License

Distributed under the AGPLv3. See the LICENSE file for more info.
