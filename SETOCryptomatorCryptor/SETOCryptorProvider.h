//
//  SETOCryptorProvider.h
//  SETOCryptomatorCryptor
//
//  Created by Tobias Hagemann on 23/06/16.
//  Copyright © 2016 setoLabs. All rights reserved.
//

#import <Foundation/Foundation.h>

@class SETOCryptor, SETOMasterKey;

extern NSString *const kSETOCryptorProviderErrorDomain;

typedef NS_ENUM(NSInteger, SETOCryptorProviderErrorDomain) {
	SETOCryptorProviderUnsupportedVaultFormatError,
	SETOCryptorProviderInvalidPasswordError
};

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

@end
