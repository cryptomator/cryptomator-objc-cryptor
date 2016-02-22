![SETOCryptomatorCryptor](SETOCryptomatorCryptor.png)

[![Cocoapods Compatible](https://img.shields.io/cocoapods/v/SETOCryptomatorCryptor.svg)](https://img.shields.io/cocoapods/v/SETOCryptomatorCryptor.svg)
[![Platform](https://img.shields.io/cocoapods/p/SETOCryptomatorCryptor.svg?style=flat)](http://cocoadocs.org/docsets/SETOCryptomatorCryptor)
[![Twitter](https://img.shields.io/badge/twitter-@Cryptomator-blue.svg?style=flat)](http://twitter.com/Cryptomator)

SETOCryptomatorCryptor is an iOS crypto framework to access Cryptomator vaults. For more information on the security details visit [cryptomator.org](https://cryptomator.org/#security).

## Requirements

* iOS 8.0 or higher
* ARC enabled

## Installation

The easiest way to use SETOCryptomatorCryptor in your app is via [CocoaPods](http://cocoapods.org/ "CocoaPods").

1. Add the following line in the project's Podfile file: `pod 'SETOCryptomatorCryptor', '~> 1.0'`
2. Run the command `pod install` from the Podfile folder directory.

## Usage

### SETOCryptomatorCryptor

`SETOCryptomatorCryptor` is the core class for cryptographic operations on Cryptomator vaults.

#### Initialization and Unlocking

```objective-c
NSString *password = ...;
SETOMasterKey *masterKey = [SETOCryptomatorCryptor newMasterKeyForPassword:password];
SETOCryptomatorCryptor *cryptor = [[SETOCryptomatorCryptor alloc] initWithMasterKey:masterKey];
SETOCryptomatorCryptorUnlockResult unlockResult = [cryptor unlockWithPassword:password];
if (unlockResult == SETOCryptomatorCryptorUnlockSuccess) {
  NSLog(@"Unlock successful");
} else {
  NSLog(@"Unlock failed: %zd", unlockResult);
}
```

Actually you should call the method `newMasterKeyForPassword:` from a background thread, as random number generation will benefit from UI interaction.

```objective-c
NSString *password = ...;
dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
  SETOMasterKey *masterKey = [SETOCryptomatorCryptor newMasterKeyForPassword:password];
  dispatch_async(dispatch_get_main_queue(), ^{
    // do the rest here
  });
});
```

#### Directory ID Encryption

```objective-c
SETOCryptomatorCryptor *cryptor = ...;
NSString *directoryId = ...;
NSString *encryptedDirectoryId = [cryptor encryptDirectoryId:directoryId];
```

#### Filename Encryption and Decryption

```objective-c
SETOCryptomatorCryptor *cryptor = ...;
NSString *filename = ...;
NSString *directoryId = ...;
NSString *encryptedFilename = [cryptor encryptFilename:filename insideDirectoryWithId:directoryId];
NSString *decryptedFilename = [cryptor decryptFilename:encryptedFilename insideDirectoryWithId:directoryId];
```

#### File Content Authentication

```objective-c
SETOCryptomatorCryptor *cryptor = ...;
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
SETOCryptomatorCryptor *cryptor = ...;
NSString *plaintextFilePath = ...;
NSString *ciphertextFilePath = ...;
[cryptor encryptFileAtPath:plaintextFilePath toPath:ciphertextFilePath callback:^(NSError *error) {
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
SETOCryptomatorCryptor *cryptor = ...;
NSString *ciphertextFilePath = ...;
NSString *plaintextFilePath = ...;
[cryptor decryptFileAtPath:ciphertextFilePath toPath:plaintextFilePath callback:^(NSError *error) {
  if (error) {
    NSLog(@"Decryption Error: %@", error);
  } else {
    NSLog(@"Decryption Success");
  }
} progress:^(CGFloat progress) {
  NSLog(@"Decryption Progress: %.2f", progress);
}];
```

### SETOAsyncCryptomatorCryptor

`SETOAsyncCryptomatorCryptor` is a `SETOCryptomatorCryptor` decorator for running file content encryption and decryption operations asynchronously. It's useful for cryptographic operations on large files without blocking the main thread.

Create and initialize `SETOAsyncCryptomatorCryptor` using `initWithMasterKey:queue:` to specify a dispatch queue. If you're initializing with the designated initializer `initWithMasterKey:`, the dispatch queue will be set to `dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0)`.

### SETOMasterKey

`SETOMasterKey` holds the information necessary for the master key. All properties are immutable to prevent accidental changes. Use `updateFromJsonData:` or `updateFromDictionary:` to modify the properties in bulk. Use the convenience method `dictionaryRepresentation`, e.g. for persisting the master key.

## License

Distributed under the MIT license. See the LICENSE file for more info.

## Contact

- https://cryptomator.org/
- info@cryptomator.org
- https://twitter.com/Cryptomator
