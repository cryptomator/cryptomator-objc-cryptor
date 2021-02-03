//
//  SETOCryptor.h
//  SETOCryptomatorCryptor
//
//  Created by Sebastian Stenzel on 14.02.15.
//  Copyright © 2015-2017 Skymatic. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>

@class SETOMasterKey;

extern NSString *const kSETOCryptorErrorDomain;

typedef NS_ENUM(NSInteger, SETOCryptorError) {
	SETOCryptorCorruptedFileHeaderError,
	SETOCryptorAuthenticationFailedError,
	SETOCryptorEncryptionFailedError,
	SETOCryptorDecryptionFailedError
};

typedef void (^SETOCryptorCompletionCallback)(NSError *error);
typedef void (^SETOCryptorProgressCallback)(CGFloat progress);

/**
 *  @c SETOCryptor is the core class for cryptographic operations on Cryptomator vaults.
 */
@interface SETOCryptor : NSObject

/**---------------------
 *  @name Initialization
 *----------------------
 */

/**
 *  Creates and initializes a @c SETOCryptor object with the specified master key.
 *
 *  @param masterKey The master key.
 *
 *  @return The newly-initialized cryptor.
 */
- (instancetype)initWithMasterKey:(SETOMasterKey *)masterKey NS_DESIGNATED_INITIALIZER;

/**
 *  Unavailable initialization method, use -initWithMasterKey: instead.
 *
 *  @see -initWithMasterKey:
 */
- (instancetype)init NS_UNAVAILABLE;

/**-------------------------------------
 *  @name Path Encryption and Decryption
 *--------------------------------------
 */

/**
 *  Encrypts directory ID.
 *
 *  @param directoryId An arbitrary directory ID to be passed to one-way hash function.
 *
 *  @return Constant length string that is unlikely to collide with any other name.
 */
- (NSString *)encryptDirectoryId:(NSString *)directoryId;

/**
 *  Encrypts filename.
 *
 *  @param filename    Original filename including cleartext file extension.
 *  @param directoryId Directory ID that will be used as associated data. It will not get encrypted but needs to be provided during decryption.
 *
 *  @return Encrypted filename without any file extension.
 */
- (NSString *)encryptFilename:(NSString *)filename insideDirectoryWithId:(NSString *)directoryId;

/**
 *  Decrypts filename.
 *
 *  @param filename    Ciphertext only. Any additional strings like file extensions need to be stripped first.
 *  @param directoryId The same directed ID used during encryption as associated data.
 *
 *  @return Decrypted filename, probably including its cleartext file extension.
 */
- (NSString *)decryptFilename:(NSString *)filename insideDirectoryWithId:(NSString *)directoryId;

/**---------------------------------------------
 *  @name File Content Encryption and Decryption
 *----------------------------------------------
 */

/**
 *  Authenticate file content.
 *
 *  @param path             The path of a ciphertext file.
 *  @param callback         A block object to be executed when file authentication completes. This block has no return value and takes one argument: The error object describing the file authentication error that occurred, otherwise it's @p nil.
 *  @param progressCallback A block object to be executed for every chunk that has been successfully authenticated. This block has no return value and takes one argument: The progress value between @p 0.0 and @p 1.0.
 */
- (void)authenticateFileAtPath:(NSString *)path callback:(SETOCryptorCompletionCallback)callback progress:(SETOCryptorProgressCallback)progressCallback;

/**
 *  Encrypts file content.
 *
 *  @param inPath           The input path of a cleartext file.
 *  @param outPath          The output path of the ciphertext file.
 *  @param callback         A block object to be executed when file encryption completes. This block has no return value and takes one argument: The error object describing the file encryption error that occurred, otherwise it's @p nil.
 *  @param progressCallback A block object to be executed for every chunk that has been successfully encrypted. This block has no return value and takes one argument: The progress value between @p 0.0 and @p 1.0.
 */
- (void)encryptFileAtPath:(NSString *)inPath toPath:(NSString *)outPath callback:(SETOCryptorCompletionCallback)callback progress:(SETOCryptorProgressCallback)progressCallback;

/**
 *  Decrypts file content.
 *
 *  @param inPath           The input path of a ciphertext file.
 *  @param outPath          The output path of the cleartext file.
 *  @param callback         A block object to be executed when file decryption completes. This block has no return value and takes one argument: The error object describing the file decryption error that occurred, otherwise it's @p nil.
 *  @param progressCallback A block object to be executed for every chunk that has been successfully decrypted. This block has no return value and takes one argument: The progress value between @p 0.0 and @p 1.0.
 */
- (void)decryptFileAtPath:(NSString *)inPath toPath:(NSString *)outPath callback:(SETOCryptorCompletionCallback)callback progress:(SETOCryptorProgressCallback)progressCallback;

/**----------------------------
 *  @name File Size Calculation
 *-----------------------------
 */

/**
 *  Calculates ciphertext size from cleartext size.
 *
 *  @param cleartextSize Size of the unencrypted payload.
 *
 *  @return Ciphertext size of a @p cleartextSize -sized cleartext encrypted with this cryptor. Not including the file header.
 */
- (NSUInteger)ciphertextSizeFromCleartextSize:(NSUInteger)cleartextSize;

/**
 *  Calculates ciphertext size from cleartext size.
 *
 *  @param ciphertextSize Size of the encrypted payload. Not including the file header.
 *
 *  @return Cleartext size of a @p ciphertextSize -sized ciphertext decrypted with this cryptor.
 */
- (NSUInteger)cleartextSizeFromCiphertextSize:(NSUInteger)ciphertextSize;

@end
