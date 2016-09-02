//
//  SETOCryptorProvider.m
//  SETOCryptomatorCryptor
//
//  Created by Tobias Hagemann on 23/06/16.
//  Copyright © 2016 setoLabs. All rights reserved.
//

#import "SETOCryptorProvider.h"
#import "SETOCryptorV3.h"
#import "SETOCryptorV5.h"
#import "SETOMasterKey.h"

#import "SETOCryptoSupport.h"

#import <CommonCrypto/CommonDigest.h>
#import <CommonCrypto/CommonHMAC.h>
#import <openssl/evp.h>
#import "e_aeswrap.h"
#import "crypto_scrypt.h"

NSString *const kSETOCryptorProviderErrorDomain = @"SETOCryptorProviderErrorDomain";

int const kSETOCryptorProviderKeyLength = 256;

typedef NS_ENUM(NSInteger, SETOCryptorSupportedVersion) {
	SETOCryptorVersion3 = 3,
	SETOCryptorVersion4 = 4,
	SETOCryptorVersion5 = 5
};

NSInteger const kSETOCryptorCurrentVersion = SETOCryptorVersion5;
NSInteger const kSETOCryptorMinimumSupportedVersion = SETOCryptorVersion3;

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
	return [SETOCryptorProvider cryptorWithPrimaryMasterKey:primaryMasterKey macMasterKey:macMasterKey forVersion:kSETOCryptorCurrentVersion];
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

	BOOL versionMacsEqual = YES;
	if (masterKey.version >= SETOCryptorVersion5) {
		// calculate mac over version:
		unsigned char *version;
		int_to_big_endian_bytes(masterKey.version, version);
		unsigned char calculatedVersionMac[CC_SHA256_DIGEST_LENGTH];
		CCHmacContext versionHmacContext;
		CCHmacInit(&versionHmacContext, kCCHmacAlgSHA256, unwrappedMacMasterKeyBuffer, unwrappedMacMasterKeyLength);
		CCHmacUpdate(&versionHmacContext, version, sizeof(int32_t));
		CCHmacFinal(&versionHmacContext, calculatedVersionMac);

		// constant time comparison of version mac:
		unsigned char *expectedVersionMac = (unsigned char *)masterKey.versionMac.bytes;
		versionMacsEqual = compare_bytes(calculatedVersionMac, expectedVersionMac, CC_SHA256_DIGEST_LENGTH);
	}

	// clean up:
	for (int i = 0; i < unwrappedPrimaryMasterKeyLength; i++) {
		unwrappedPrimaryMasterKeyBuffer[i] = 0;
	}
	for (int i = 0; i < unwrappedMacMasterKeyLength; i++) {
		unwrappedMacMasterKeyBuffer[i] = 0;
	}

	// done:
	if (versionMacsEqual) {
		return [SETOCryptorProvider cryptorWithPrimaryMasterKey:primaryMasterKey macMasterKey:macMasterKey forVersion:masterKey.version];
	} else {
		if (error) {
			*error = [NSError errorWithDomain:kSETOCryptorProviderErrorDomain code:SETOCryptorProviderUnauthenticKeyVersionError userInfo:nil];
		}
		return nil;
	}
}

+ (NSUInteger)cleartextSizeFromCiphertextSize:(NSUInteger)ciphertextSize withCryptor:(SETOCryptor *)cryptor {
	if (cryptor.version < SETOCryptorVersion5) {
		NSLog(@"+[SETOCryptorProvider cleartextSizeFromCiphertextSize:withCryptor:] not defined for cryptor version %zd", cryptor.version);
		return NSUIntegerMax;
	}
	NSUInteger cleartextChunkSize = cryptor.cleartextChunkSize;
	NSUInteger ciphertextChunkSize = cryptor.ciphertextChunkSize;
	NSUInteger overheadPerChunk = ciphertextChunkSize - cleartextChunkSize;
	NSUInteger numFullChunks = ciphertextSize / ciphertextChunkSize; // floor by int-truncation
	NSUInteger additionalCiphertextBytes = ciphertextSize % ciphertextChunkSize;
	if (additionalCiphertextBytes > 0 && additionalCiphertextBytes <= overheadPerChunk) {
		NSLog(@"+[SETOCryptorProvider cleartextSizeFromCiphertextSize:withCryptor:] not defined for input value %tu", ciphertextSize);
		return NSUIntegerMax;
	}
	NSUInteger additionalCleartextBytes = (additionalCiphertextBytes == 0) ? 0 : additionalCiphertextBytes - overheadPerChunk;
	return cleartextChunkSize * numFullChunks + additionalCleartextBytes;
}

+ (NSUInteger)ciphertextSizeFromCleartextSize:(NSUInteger)cleartextSize withCryptor:(SETOCryptor *)cryptor {
	if (cryptor.version < SETOCryptorVersion5) {
		NSLog(@"+[SETOCryptorProvider cleartextSizeFromCiphertextSize:withCryptor:] not defined for cryptor version %zd", cryptor.version);
		return NSUIntegerMax;
	}
	NSUInteger cleartextChunkSize = cryptor.cleartextChunkSize;
	NSUInteger ciphertextChunkSize = cryptor.ciphertextChunkSize;
	NSUInteger overheadPerChunk = ciphertextChunkSize - cleartextChunkSize;
	NSUInteger numFullChunks = cleartextSize / cleartextChunkSize; // floor by int-truncation
	NSUInteger additionalCleartextBytes = cleartextSize % cleartextChunkSize;
	NSUInteger additionalCiphertextBytes = (additionalCleartextBytes == 0) ? 0 : additionalCleartextBytes + overheadPerChunk;
	return ciphertextChunkSize * numFullChunks + additionalCiphertextBytes;
}

#pragma mark - Convenience

+ (SETOCryptor *)cryptorWithPrimaryMasterKey:(NSData *)primaryMasterKey macMasterKey:(NSData *)macMasterKey forVersion:(SETOCryptorSupportedVersion)version {
	switch (version) {
		case SETOCryptorVersion3:
		case SETOCryptorVersion4:
			return [[SETOCryptorV3 alloc] initWithPrimaryMasterKey:primaryMasterKey macMasterKey:macMasterKey version:version];
		case SETOCryptorVersion5:
			return [[SETOCryptorV5 alloc] initWithPrimaryMasterKey:primaryMasterKey macMasterKey:macMasterKey version:version];
		default:
			return nil;
	}
}

+ (BOOL)supportsVersion:(NSInteger)version {
	return version >= kSETOCryptorMinimumSupportedVersion && version <= kSETOCryptorCurrentVersion;
}

@end
