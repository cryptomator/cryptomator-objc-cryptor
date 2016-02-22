//
//  SETOCryptomatorCryptor.h
//  SETOCryptomatorCryptor
//
//  Created by Sebastian Stenzel on 14/02/15.
//  Copyright © 2015-2016 setoLabs. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>

extern NSString *const kSETOCryptomatorCryptorErrorDomain;

typedef NS_ENUM(NSInteger, SETOCryptomatorCryptorUnlockResult) {
	SETOCryptomatorCryptorUnlockSuccess,
	SETOCryptomatorCryptorUnlockVersionMismatch,
	SETOCryptomatorCryptorUnlockInvalidMasterKey,
	SETOCryptomatorCryptorUnlockWrongPassword
};

typedef NS_ENUM(NSInteger, SETOCryptomatorCryptorError) {
	SETOCryptomatorCryptorCorruptedFileHeaderError,
	SETOCryptomatorCryptorAuthenticationFailedError,
	SETOCryptomatorCryptorEncryptionFailedError,
	SETOCryptomatorCryptorDecryptionFailedError
};

typedef void (^SETOCryptomatorCryptorCompletionCallback)(NSError *error);
typedef void (^SETOCryptomatorCryptorProgressCallback)(CGFloat progress);

@class SETOMasterKey;

/**
 *  `SETOCryptomatorCryptor` is the core class for cryptographic operations on Cryptomator vaults.
 */
@interface SETOCryptomatorCryptor : NSObject

/**-----------------------------------
 *  @name Initialization and Unlocking
 *------------------------------------
 */

/**
 *  Creates and initializes a `SETOMasterKey` object with the specified password.
 *
 *  @param password The user-assigned password.
 *
 *  @return The newly-initalized master key based on the specified password.
*/
+ (SETOMasterKey *)newMasterKeyForPassword:(NSString *)password;

/**
 *  Creates and initializes a `SETOCryptomatorCryptor` object with the specified master key.
 *
 *  @param masterKey The master key for initializing the cryptor.
 *
 *  @return The newly-initialized cryptor.
 */
- (instancetype)initWithMasterKey:(SETOMasterKey *)masterKey NS_DESIGNATED_INITIALIZER;

/**
 *  Unavailable initialization method, use initWithMasterKey: instead.
 *
 *  @see -initWithMasterKey:
 */
- (instancetype)init NS_UNAVAILABLE;

/**
 *  Unlocks this cryptor with the specified password. If unlock is successful, the primary and mac master keys will be set internally for all succeeding cryptographic operations.
 *
 *  @param password The user-assigned password to unlock the cryptor.
 *
 *  @return A `SETOCryptomatorCryptorUnlockResult`.
 */
- (SETOCryptomatorCryptorUnlockResult)unlockWithPassword:(NSString *)password;

/**-------------------------------------
 *  @name Path Encryption and Decryption
 *--------------------------------------
 */

/**
 *  Encrypts the specified plaintext directory id and returns the result.
 *
 *  @param directoryId The plaintext directory id that is going to be encrypted.
 *
 *  @return The encrypted directory id.
 */
- (NSString *)encryptDirectoryId:(NSString *)directoryId;

/**
 *  Encrypts the specified plaintext filename inside given directory with id and returns the result.
 *
 *  @param filename The plaintext filename that is going to be encrypted.
 *  @param directoryId The plaintext directory id.
 *
 *  @return The encrypted filename.
 */
- (NSString *)encryptFilename:(NSString *)filename insideDirectoryWithId:(NSString *)directoryId;

/**
 *  Decrypts the specified ciphertext filename inside given directory with id and returns the result.
 *
 *  @param filename The ciphertext filename that is going to be decrypted.
 *  @param directoryId The plaintext directory id.
 *
 *  @return The decrypted filename.
 */
- (NSString *)decryptFilename:(NSString *)filename insideDirectoryWithId:(NSString *)directoryId;

/**---------------------------------------------
 *  @name File Content Encryption and Decryption
 *----------------------------------------------
 */

/**
 *  Authenticate file at given path.
 *
 *  @param path             The path of an encrypted file.
 *  @param callback         A block object to be executed when file authentication completes. This block has no return value and takes one argument: The error object describing the file authentication error that occurred, otherwise it's `nil`.
 *  @param progressCallback A block object to be executed for every chunk that has been successfully authenticated. This block has no return value and takes one argument: The progress value between `0.0` and `1.0`.
 */
- (void)authenticateFileAtPath:(NSString *)path callback:(SETOCryptomatorCryptorCompletionCallback)callback progress:(SETOCryptomatorCryptorProgressCallback)progressCallback;

/**
 *  Encrypt file at given path to output path.
 *
 *  @param inPath           The input path of a file.
 *  @param outPath          The output path of the encrypted file.
 *  @param callback         A block object to be executed when file encryption completes. This block has no return value and takes one argument: The error object describing the file encryption error that occurred, otherwise it's `nil`.
 *  @param progressCallback A block object to be executed for every chunk that has been successfully encrypted. This block has no return value and takes one argument: The progress value between `0.0` and `1.0`.
 */
- (void)encryptFileAtPath:(NSString *)inPath toPath:(NSString *)outPath callback:(SETOCryptomatorCryptorCompletionCallback)callback progress:(SETOCryptomatorCryptorProgressCallback)progressCallback;

/**
 *  Decrypt file at given path to output path.
 *
 *  @param inPath           The input path of an encrypted file.
 *  @param outPath          The output path of the decrypted file.
 *  @param callback         A block object to be executed when file decryption completes. This block has no return value and takes one argument: The error object describing the file decryption error that occurred, otherwise it's `nil`.
 *  @param progressCallback A block object to be executed for every chunk that has been successfully decrypted. This block has no return value and takes one argument: The progress value between `0.0` and `1.0`.
 */
- (void)decryptFileAtPath:(NSString *)inPath toPath:(NSString *)outPath callback:(SETOCryptomatorCryptorCompletionCallback)callback progress:(SETOCryptomatorCryptorProgressCallback)progressCallback;

@end
