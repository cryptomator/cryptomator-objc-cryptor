//
//  SETOCryptorProvider.h
//  SETOCryptomatorCryptor
//
//  Created by Tobias Hagemann on 03.02.21.
//  Copyright © 2021 Skymatic. All rights reserved.
//

#import <Foundation/Foundation.h>

@class SETOMasterKey, SETOCryptor;

extern NSString *const kSETOCryptorProviderErrorDomain;

typedef NS_ENUM(NSInteger, SETOCryptorProviderError) {
	SETOCryptorProviderUnsupportedVaultFormatError
};

/**
 *  @c SETOCryptorProvider is a factory for @c SETOCryptor objects.
 */
@interface SETOCryptorProvider : NSObject

/**
 *  Provides a @c SETOCryptor object with the specified master key for the specified vault version.
 *
 *  @param masterKey    The master key.
 *  @param vaultVersion The user-assigned password to unlock the cryptor.
 *  @param error        On input, a pointer to an error object. If an error occurs, this pointer is set to an actual error object containing the error information. You may specify @p NULL for this parameter if you do not want the error information.
 *
 *  @return The newly-initialized cryptor.
 */
+ (SETOCryptor *)cryptorWithMasterKey:(SETOMasterKey *)masterKey forVaultVersion:(NSInteger)vaultVersion error:(NSError **)error;

@end
