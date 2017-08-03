//
//  SETOCryptorProvider.h
//  SETOCryptomatorCryptor
//
//  Created by Tobias Hagemann on 23.06.16.
//  Copyright © 2015-2017 Skymatic. All rights reserved.
//

#import <Foundation/Foundation.h>

@class SETOCryptor, SETOMasterKey;

extern NSString *const kSETOCryptorProviderErrorDomain;

typedef NS_ENUM(NSInteger, SETOCryptorProviderError) {
	SETOCryptorProviderUnsupportedVaultFormatError,
	SETOCryptorProviderInvalidPasswordError,
	SETOCryptorProviderUnauthenticKeyVersionError
};

extern NSInteger const kSETOCryptorCurrentVersion;
extern NSInteger const kSETOCryptorMinimumSupportedVersion;

/**
 *  @c SETOCryptorProvider is a factory for @c SETOCryptor objects.
 */
@interface SETOCryptorProvider : NSObject

/**
 *  Creates and initializes a @c SETOCryptor object for the current version with a secure random primary and mac master key.
 *
 *  @return The newly-initialized cryptor.
 */
+ (SETOCryptor *)newCryptor;

/**
 *  Creates and initializes a @c SETOCryptor object from the specified master key with the specified password. This is equivalent to an unlocking attempt. If an error occurs, this method returns @p nil and assigns an appropriate error object to the @p error parameter.
 *
 *  @param masterKey The master key.
 *  @param password  The user-assigned password to unlock the cryptor.
 *  @param error     On input, a pointer to an error object. If an error occurs, this pointer is set to an actual error object containing the error information. You may specify @p NULL for this parameter if you do not want the error information.
 *
 *  @return The newly-initialized cryptor.
 */
+ (SETOCryptor *)cryptorFromMasterKey:(SETOMasterKey *)masterKey withPassword:(NSString *)password error:(NSError **)error;

/**
 *  Creates and initializes a @c SETOCryptor object from the specified master key with the specified password and pepper. This is equivalent to an unlocking attempt. If an error occurs, this method returns @p nil and assigns an appropriate error object to the @p error parameter.
 *
 *  @param masterKey The master key.
 *  @param password  The user-assigned password to unlock the cryptor.
 *  @param pepper    An application-specific pepper added to the salt during key derivation (if applicable).
 *  @param error     On input, a pointer to an error object. If an error occurs, this pointer is set to an actual error object containing the error information. You may specify @p NULL for this parameter if you do not want the error information.
 *
 *  @return The newly-initialized cryptor.
 */
+ (SETOCryptor *)cryptorFromMasterKey:(SETOMasterKey *)masterKey withPassword:(NSString *)password pepper:(NSData *)pepper error:(NSError **)error;

/**
 *  Calculates the size of the cleartext resulting from the given ciphertext decrypted with the given @c SETOCryptor object.
 *
 *  @param ciphertextSize Pure payload ciphertext. Not including the length of the header.
 *  @param cryptor        The cryptor.
 *
 *  @return Cleartext length of a @p ciphertextSize sized ciphertext decrypted with @p cryptor.
 */
+ (NSUInteger)cleartextSizeFromCiphertextSize:(NSUInteger)ciphertextSize withCryptor:(SETOCryptor *)cryptor;

/**
 *  Calculates the size of the ciphertext resulting from the given cleartext encrypted with the given @c SETOCryptor object.
 *
 *  @param cleartextSize The cleartext size.
 *  @param cryptor       The cryptor.
 *
 *  @return Ciphertext length of a @p cleartextSize sized cleartext encrypted with @p cryptor. Not including the length of the header.
 */
+ (NSUInteger)ciphertextSizeFromCleartextSize:(NSUInteger)cleartextSize withCryptor:(SETOCryptor *)cryptor;

@end
