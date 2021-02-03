![SETOCryptomatorCryptor](SETOCryptomatorCryptor.png)

[![Cocoapods Compatible](https://img.shields.io/cocoapods/v/SETOCryptomatorCryptor.svg)](https://img.shields.io/cocoapods/v/SETOCryptomatorCryptor.svg)
[![Platform](https://img.shields.io/cocoapods/p/SETOCryptomatorCryptor.svg?style=flat)](http://cocoadocs.org/docsets/SETOCryptomatorCryptor)
[![Twitter](https://img.shields.io/badge/twitter-@Cryptomator-blue.svg?style=flat)](http://twitter.com/Cryptomator)

SETOCryptomatorCryptor is an iOS crypto library to access Cryptomator vaults. For more information on the security details, visit [docs.cryptomator.org](https://docs.cryptomator.org/en/1.5/security/architecture/).

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

### SETOMasterKey

`SETOMasterKey` is a class that only contains the key material for AES encryption/decryption and MAC authentication.

#### Constructor

This will create a new master key with secure random bytes.

```objective-c
SETOMasterKey *masterKey = [[SETOMasterKey alloc] init];
```

You should call the constructor from a background thread, as random number generation will benefit from UI interaction.

```objective-c
dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
  SETOMasterKey *masterKey = [[SETOMasterKey alloc] init];
  dispatch_async(dispatch_get_main_queue(), ^{
    // do the rest here
  });
});
```

Another way is to create a master key from raw bytes.

```objective-c
NSData *aesMasterKey = ...;
NSData *macMasterKey = ...;
SETOMasterKey *masterKey = [[SETOMasterKey alloc] initWithAESMasterKey:aesMasterKey macMasterKey:macMasterKey];
```

### SETOMasterKeyFile

`SETOMasterKeyFile` is a representation of the master key file. With that, you can unlock a master key file (and get a `SETOMasterKey`) or lock a master key file (and serialize it as JSON).

#### Constructor

Create a master key file with content provided from JSON data:

```objective-c
NSData *jsonData = ...;
SETOMasterKeyFile *masterkeyFile = [[SETOMasterKeyFile alloc] initWithContentFromJSONData:jsonData];
```

#### Unlock

When you have a master key file, you can attempt an unlock. When successful, it unwraps the stored encryption and MAC keys into the master key, which can be used for the cryptor.

```objective-c
SETOMasterKeyFile *masterkeyFile = ...;
NSString *passphrase = ...;
NSData *pepper = ...; // optional
NSInteger expectedVaultVersion = ...; // use NSNotFound if a version check should be skipped
NSError *error;
SETOMasterKey *masterKey = [masterkeyFile unlockWithPassphrase:passphrase pepper:pepper expectedVaultVersion:expectedVaultVersion error:&error];
```

#### Lock

For persisting the master key, use this method to export its encrypted/wrapped master key and other metadata as JSON data.

```objective-c
SETOMasterKey *masterKey = ...;
NSInteger vaultVersion = ...;
NSString *passphrase = ...;
NSData *pepper = ...; // optional
uint64_t scryptCostParam = ...; // use kSETOMasterKeyFileDefaulScryptCostParam if you are not sure
NSError *error;
NSData *jsonData = [SETOMasterKeyFile lockMasterKey:masterKey withVaultVersion:vaultVersion passphrase:passphrase pepper:pepper scryptCostParam:scryptCostParam error:&error];
```

You should call the lock method from a background thread, as random number generation will benefit from UI interaction.

```objective-c
dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
  SETOMasterKey *masterKey = ...;
  NSInteger vaultVersion = ...;
  NSString *passphrase = ...;
  NSData *pepper = ...; // optional
  uint64_t scryptCostParam = ...; // use kSETOMasterKeyFileDefaulScryptCostParam if you are not sure
  NSError *error;
  NSData *jsonData = [SETOMasterKeyFile lockMasterKey:masterKey withVaultVersion:vaultVersion passphrase:passphrase pepper:pepper scryptCostParam:scryptCostParam error:&error];
  dispatch_async(dispatch_get_main_queue(), ^{
    // do the rest here
  });
});
```

### SETOCryptorProvider

`SETOCryptorProvider` is a factory for `SETOCryptor` objects. Always use the factory for creating `SETOCryptor` instances.

#### Factory

```objective-c
SETOMasterKey *masterKey = ...;
NSError *error;
SETOCryptor *cryptor = [SETOCryptorProvider cryptorWithMasterKey:masterKey forVaultVersion:7 error:&error];
```

### SETOCryptor

`SETOCryptor` is the core class for cryptographic operations on Cryptomator vaults. This is an abstract class, so you should use `SETOCryptorProvider` to create a `SETOCryptor` instance.

#### Directory ID Encryption

Encrypt the directory ID in order to determine the encrypted directory path.

```objective-c
SETOCryptor *cryptor = ...;
NSString *directoryId = ...;
NSString *encryptedDirectoryId = [cryptor encryptDirectoryId:directoryId];
```

#### Filename Encryption and Decryption

Encrypt and decrypt filenames by providing a directory ID.

```objective-c
SETOCryptor *cryptor = ...;
NSString *filename = ...;
NSString *directoryId = ...;
NSString *encryptedFilename = [cryptor encryptFilename:filename insideDirectoryWithId:directoryId];
NSString *decryptedFilename = [cryptor decryptFilename:encryptedFilename insideDirectoryWithId:directoryId];
```

#### File Content Authentication

Authenticate file content to verify its integrity.

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

Encrypt file content via paths.

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

Decrypt file content via paths.

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

#### File Size Calculation

Beginning with vault version 5, you can determine the cleartext and ciphertext sizes in O(1). Reading out the file sizes before vault version 5 is theoretically possible, but not supported by this library.

```objective-c
SETOCryptor *cryptor = ...;
NSUInteger size = ...;
NSUInteger ciphertextSize = [cryptor ciphertextSizeFromCleartextSize:size];
NSUInteger cleartextSize = [cryptor cleartextSizeFromCiphertextSize:ciphertextSize];
```

### SETOAsyncCryptor

`SETOAsyncCryptor` is a `SETOCryptor` decorator for running file content encryption and decryption operations asynchronously. It's useful for cryptographic operations on large files without blocking the main thread.

Create and initialize `SETOAsyncCryptor` using `initWithCryptor:queue:` to specify a dispatch queue. If you're initializing with the convenience initializer `initWithCryptor:`, a serial queue (utility QoS class) will be created and used.

## Contributing to Cryptomator

Please read our [contribution guide](https://github.com/cryptomator/cryptomator-objc-cryptor/blob/master/CONTRIBUTING.md), if you would like to report a bug, ask a question or help us with coding.

## Code of Conduct

Help us keep Cryptomator open and inclusive. Please read and follow our [Code of Conduct](https://github.com/cryptomator/cryptomator-objc-cryptor/blob/master/CODE_OF_CONDUCT.md).

## License

Distributed under the AGPLv3. See the LICENSE file for more info.
