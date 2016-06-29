//
//  SETOCryptorProvider.m
//  SETOCryptomatorCryptor
//
//  Created by Tobias Hagemann on 23/06/16.
//  Copyright © 2016 setoLabs. All rights reserved.
//

#import "SETOCryptorProvider.h"
#import "SETOCryptorV3.h"
#import "SETOMasterKey.h"

#import <openssl/evp.h>
#import "e_aeswrap.h"
#import "crypto_scrypt.h"

NSString *const kSETOCryptorProviderErrorDomain = @"SETOCryptorProviderErrorDomain";

NSUInteger kSETOCryptorProviderCurrentVersion = 4;
int const kSETOCryptorProviderKeyLength = 256;

@implementation SETOCryptorProvider

+ (SETOCryptor *)newCryptor {
	if ([NSThread isMainThread]) {
		NSLog(@"Warning: This method should be called from a background thread, as random number generation will benefit from UI interaction.");
	}

	// create random bytes for primary master key:
	unsigned char primaryMasterKeyBuffer[kSETOCryptorProviderKeyLength / 8];
	if (SecRandomCopyBytes(kSecRandomDefault, sizeof(primaryMasterKeyBuffer), primaryMasterKeyBuffer) == -1) {
		NSLog(@"Unable to create random bytes for primaryMasterKeyBuffer.");
		return nil;
	}

	// create random bytes for mac master key:
	unsigned char macMasterKeyBuffer[kSETOCryptorProviderKeyLength / 8];
	if (SecRandomCopyBytes(kSecRandomDefault, sizeof(macMasterKeyBuffer), macMasterKeyBuffer) == -1) {
		NSLog(@"Unable to create random bytes for macMasterKeyBuffer.");
		return nil;
	}

	// initialize master keys:
	NSData *primaryMasterKey = [NSData dataWithBytes:primaryMasterKeyBuffer length:sizeof(primaryMasterKeyBuffer)];
	NSData *macMasterKey = [NSData dataWithBytes:macMasterKeyBuffer length:sizeof(macMasterKeyBuffer)];

	// done:
	return [SETOCryptorProvider cryptorWithPrimaryMasterKey:primaryMasterKey macMasterKey:macMasterKey forVersion:kSETOCryptorProviderCurrentVersion];
}

+ (SETOCryptor *)cryptorFromMasterKey:(SETOMasterKey *)masterKey withPassword:(NSString *)password error:(NSError **)error {
	NSParameterAssert(masterKey);
	NSParameterAssert(password);

	// check master key version:
	if (![SETOCryptorProvider supportsVersion:masterKey.version]) {
		if (error) {
			*error = [NSError errorWithDomain:kSETOCryptorProviderErrorDomain code:SETOCryptorProviderUnsupportedVaultFormatError userInfo:nil];
		}
		return nil;
	}

	// scrypt key derivation:
	NSData *passwordData = [password dataUsingEncoding:NSUTF8StringEncoding];
	NSData *scryptSalt = masterKey.scryptSalt;
	uint64_t costParam = masterKey.scryptCostParam;
	uint32_t blockSize = (uint32_t)masterKey.scryptBlockSize;
	unsigned char kekBytes[kSETOCryptorProviderKeyLength / 8];
	crypto_scrypt(passwordData.bytes, passwordData.length, scryptSalt.bytes, scryptSalt.length, costParam, blockSize, 1, kekBytes, sizeof(kekBytes));

	// unwrap primary and mac master keys:
	const EVP_CIPHER *cipher = EVP_aes_256_ecb();
	EVP_CIPHER_CTX ctx;
	EVP_CIPHER_CTX_init(&ctx);
	EVP_DecryptInit_ex(&ctx, cipher, NULL, kekBytes, NULL);

	NSData *wrappedPrimaryMasterKey = masterKey.primaryMasterKey;
	unsigned char unwrappedPrimaryMasterKeyBuffer[kSETOCryptorProviderKeyLength / 8];
	int unwrappedPrimaryMasterKeyLength = EVP_aes_unwrap_key(&ctx, NULL, unwrappedPrimaryMasterKeyBuffer, wrappedPrimaryMasterKey.bytes, (unsigned int)wrappedPrimaryMasterKey.length);

	NSData *wrappedMacMasterKey = masterKey.macMasterKey;
	unsigned char unwrappedMacMasterKeyBuffer[kSETOCryptorProviderKeyLength / 8];
	int unwrappedMacMasterKeyLength = EVP_aes_unwrap_key(&ctx, NULL, unwrappedMacMasterKeyBuffer, wrappedMacMasterKey.bytes, (unsigned int)wrappedMacMasterKey.length);

	EVP_CIPHER_CTX_cleanup(&ctx);

	// check for key lengths, zero length means password is invalid:
	if (unwrappedPrimaryMasterKeyLength == 0 || unwrappedMacMasterKeyLength == 0) {
		if (error) {
			*error = [NSError errorWithDomain:kSETOCryptorProviderErrorDomain code:SETOCryptorProviderInvalidPasswordError userInfo:nil];
		}
		return nil;
	}

	// initialize master keys:
	NSData *primaryMasterKey = [NSData dataWithBytes:unwrappedPrimaryMasterKeyBuffer length:unwrappedPrimaryMasterKeyLength];
	NSData *macMasterKey = [NSData dataWithBytes:unwrappedMacMasterKeyBuffer length:unwrappedMacMasterKeyLength];

	// clean up:
	for (int i = 0; i < unwrappedPrimaryMasterKeyLength; i++) {
		unwrappedPrimaryMasterKeyBuffer[i] = 0;
	}
	for (int i = 0; i < unwrappedMacMasterKeyLength; i++) {
		unwrappedMacMasterKeyBuffer[i] = 0;
	}

	// done:
	return [SETOCryptorProvider cryptorWithPrimaryMasterKey:primaryMasterKey macMasterKey:macMasterKey forVersion:masterKey.version];
}

#pragma mark - Convenience

+ (SETOCryptor *)cryptorWithPrimaryMasterKey:(NSData *)primaryMasterKey macMasterKey:(NSData *)macMasterKey forVersion:(NSUInteger)version {
	switch (version) {
		case 3:
		case 4:
			return [[SETOCryptorV3 alloc] initWithPrimaryMasterKey:primaryMasterKey macMasterKey:macMasterKey];
		default:
			return nil;
	}
}

+ (BOOL)supportsVersion:(NSUInteger)version {
	return version >= 3 && version <= 4;
}

@end
