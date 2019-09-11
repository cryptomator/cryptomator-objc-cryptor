//
//  SETOCryptor.h
//  SETOCryptomatorCryptor
//
//  Created by Sebastian Stenzel on 14.02.15.
//  Copyright © 2015-2017 Skymatic. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>

extern NSString *const kSETOCryptorErrorDomain;

typedef NS_ENUM(NSInteger, SETOCryptorError) {
	SETOCryptorCorruptedFileHeaderError,
	SETOCryptorAuthenticationFailedError,
	SETOCryptorEncryptionFailedError,
	SETOCryptorDecryptionFailedError
};

typedef NS_ENUM(NSInteger, SETOCryptorVersion) {
	SETOCryptorVersion3 = 3,
	SETOCryptorVersion4 = 4,
	SETOCryptorVersion5 = 5,
	SETOCryptorVersion6 = 6,
	SETOCryptorVersion7 = 7
};

typedef void (^SETOCryptorCompletionCallback)(NSError *error);
typedef void (^SETOCryptorProgressCallback)(CGFloat progress);

@class SETOMasterKey;

/**
 *  @c SETOCryptor is the core class for cryptographic operations on Cryptomator vaults.
 */
@interface SETOCryptor : NSObject

@property (nonatomic, readonly) SETOCryptorVersion version;

/**---------------------
 *  @name Initialization
 *----------------------
 */

/**
 *  Creates and initializes a @c SETOCryptor object with the specified primary master key and mac master key.
 *
 *  @param primaryMasterKey The primary master key.
 *  @param macMasterKey     The MAC master key.
 *  @param version          The cryptor version.
 *
 *  @return The newly-initialized cryptor.
 */
- (instancetype)initWithPrimaryMasterKey:(NSData *)primaryMasterKey macMasterKey:(NSData *)macMasterKey version:(SETOCryptorVersion)version NS_DESIGNATED_INITIALIZER;

/**
 *  Unavailable initialization method, use -initWithPrimaryMasterKey:macMasterKey: instead.
 *
 *  @see -initWithPrimaryMasterKey:macMasterKey:
 */
- (instancetype)init NS_UNAVAILABLE;

/**
 *  Creates a @c SETOMasterKey object with the specified password.
 *
 *  @param password The user-assigned password from which the keys will be derived.
 *
 *  @return The newly-initialized master key.
 */
- (SETOMasterKey *)masterKeyWithPassword:(NSString *)password;

/**
 *  Creates a @c SETOMasterKey object with the specified password and pepper.
 *
 *  @param password The user-assigned password from which the keys will be derived.
 *  @param pepper   An application-specific pepper added to the salt during key derivation (if applicable).
 *
 *  @return The newly-initialized master key.
 */
- (SETOMasterKey *)masterKeyWithPassword:(NSString *)password pepper:(NSData *)pepper;

/**-------------------------------------
 *  @name Path Encryption and Decryption
 *--------------------------------------
 */

/**
 *  Encrypts the specified cleartext directory id and returns the result.
 *
 *  @param directoryId The cleartext directory id that is going to be encrypted.
 *
 *  @return The encrypted directory id.
 */
- (NSString *)encryptDirectoryId:(NSString *)directoryId;

/**
 *  Encrypts the specified cleartext filename inside given directory with id and returns the result.
 *
 *  @param filename The cleartext filename that is going to be encrypted.
 *  @param directoryId The cleartext directory id.
 *
 *  @return The encrypted filename.
 */
- (NSString *)encryptFilename:(NSString *)filename insideDirectoryWithId:(NSString *)directoryId;

/**
 *  Decrypts the specified ciphertext filename inside given directory with id and returns the result.
 *
 *  @param filename The ciphertext filename that is going to be decrypted.
 *  @param directoryId The cleartext directory id.
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
 *  @param callback         A block object to be executed when file authentication completes. This block has no return value and takes one argument: The error object describing the file authentication error that occurred, otherwise it's @p nil.
 *  @param progressCallback A block object to be executed for every chunk that has been successfully authenticated. This block has no return value and takes one argument: The progress value between @p 0.0 and @p 1.0.
 */
- (void)authenticateFileAtPath:(NSString *)path callback:(SETOCryptorCompletionCallback)callback progress:(SETOCryptorProgressCallback)progressCallback;

/**
 *  Encrypt file at given path to output path.
 *
 *  @param inPath           The input path of a file.
 *  @param outPath          The output path of the encrypted file.
 *  @param callback         A block object to be executed when file encryption completes. This block has no return value and takes one argument: The error object describing the file encryption error that occurred, otherwise it's @p nil.
 *  @param progressCallback A block object to be executed for every chunk that has been successfully encrypted. This block has no return value and takes one argument: The progress value between @p 0.0 and @p 1.0.
 */
- (void)encryptFileAtPath:(NSString *)inPath toPath:(NSString *)outPath callback:(SETOCryptorCompletionCallback)callback progress:(SETOCryptorProgressCallback)progressCallback;

/**
 *  Decrypt file at given path to output path.
 *
 *  @param inPath           The input path of an encrypted file.
 *  @param outPath          The output path of the decrypted file.
 *  @param callback         A block object to be executed when file decryption completes. This block has no return value and takes one argument: The error object describing the file decryption error that occurred, otherwise it's @p nil.
 *  @param progressCallback A block object to be executed for every chunk that has been successfully decrypted. This block has no return value and takes one argument: The progress value between @p 0.0 and @p 1.0.
 */
- (void)decryptFileAtPath:(NSString *)inPath toPath:(NSString *)outPath callback:(SETOCryptorCompletionCallback)callback progress:(SETOCryptorProgressCallback)progressCallback;

/**------------------
 *  @name Chunk Sizes
 *-------------------
 */

/**
 *  @return The number of cleartext bytes per chunk.
 */
- (NSUInteger)cleartextChunkSize;

/**
 *  @return The number of ciphertext bytes per chunk.
 */
- (NSUInteger)ciphertextChunkSize;

@end
