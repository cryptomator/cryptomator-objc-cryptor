//
//  SETOMasterKeyFile.h
//  SETOCryptomatorCryptor
//
//  Created by Tobias Hagemann on 28.01.21.
//  Copyright © 2021 Skymatic. All rights reserved.
//

#import <Foundation/Foundation.h>

@class SETOMasterKey;

extern NSString *const kSETOMasterKeyFileErrorDomain;

typedef NS_ENUM(NSInteger, SETOMasterKeyFileError) {
	SETOMasterKeyFileMalformedError,
	SETOMasterKeyFileInvalidPassphraseError,
	SETOMasterKeyFileUnauthenticVersionError,
	SETOMasterKeyFileKeyDerivationFailedError,
	SETOMasterKeyFileKeyWrapFailedError
};

extern uint64_t const kSETOMasterKeyFileDefaultScryptCostParam;

@interface SETOMasterKeyFile : NSObject

@property (nonatomic, readonly) uint32_t version;

/**
 *  Creates master key file with content provided from JSON data.
 *
 *  @param jsonData The JSON representation of the master key file.
 *
 *  @return New master key file instance.
 */
- (instancetype)initWithContentFromJSONData:(NSData *)jsonData;

/**
 *  Unavailable initialization method, use -initWithContentFromJSONData: instead.
 *
 *  @see -initWithContentFromJSONData:
 */
- (instancetype)init NS_UNAVAILABLE;

/**
 *  Derives a KEK from the given passphrase and the params from this master key file using scrypt and unwraps the stored encryption and MAC keys.
 *
 *  @param passphrase The passphrase used during key derivation.
 *  @param pepper     An application-specific pepper added to the scrypt's salt (if applicable).
 *  @param error      On input, a pointer to an error object. If an error occurs, this pointer is set to an actual error object containing the error information. You may specify @p NULL for this parameter if you do not want the error information.
 *
 *  @return A master key with the unwrapped keys.
 */
- (SETOMasterKey *)unlockWithPassphrase:(NSString *)passphrase pepper:(NSData *)pepper error:(NSError **)error;

/**
 *  Derives a KEK from the given passphrase and wraps the key material from master key.
 *  Then serializes the encrypted keys as well as used key derivation parameters into a JSON representation that can be stored into a master key file.
 *
 *  @param masterKey       The key to protect.
 *  @param vaultVersion    The vault version that should be stored in this master key file (for downwards compatibility).
 *  @param passphrase      The passphrase used during key derivation.
 *  @param pepper          An application-specific pepper added to the scrypt's salt (if applicable).
 *  @param scryptCostParam The work factor for the key derivation function (scrypt). Use @p kSETOMasterKeyFileDefaultScryptCostParam if you are not sure.
 *  @param error           On input, a pointer to an error object. If an error occurs, this pointer is set to an actual error object containing the error information. You may specify @p NULL for this parameter if you do not want the error information.
 *
 *  @return A JSON representation of the encrypted master key with its key derivation parameters.
 */
+ (NSData *)lockMasterKey:(SETOMasterKey *)masterKey withVaultVersion:(NSInteger)vaultVersion passphrase:(NSString *)passphrase pepper:(NSData *)pepper scryptCostParam:(uint64_t)scryptCostParam error:(NSError **)error;

@end
