//
//  SETOMasterKeyFile.m
//  SETOCryptomatorCryptor
//
//  Created by Tobias Hagemann on 28.01.21.
//  Copyright © 2021 Skymatic. All rights reserved.
//

#import "SETOMasterKeyFile.h"
#import "SETOMasterKey.h"

#import "SETOCryptoSupport.h"
#import "SETOSecureRandom.h"

#import <CommonCrypto/CommonCrypto.h>
#import <CommonCrypto/CommonHMAC.h>
#import <KZPropertyMapper/KZPropertyMapper.h>
#import <openssl/evp.h>
#import "e_aeswrap.h"
#import "crypto_scrypt.h"

NSString *const kSETOMasterKeyFileErrorDomain = @"SETOMasterKeyFileErrorDomain";

NSString *const kSETOMasterKeyFileVersionKey = @"version";
NSString *const kSETOMasterKeyFileVersionMacKey = @"versionMac";
NSString *const kSETOMasterKeyFileScryptSaltKey = @"scryptSalt";
NSString *const kSETOMasterKeyFileScryptCostParamKey = @"scryptCostParam";
NSString *const kSETOMasterKeyFileScryptBlockSizeKey = @"scryptBlockSize";
NSString *const kSETOMasterKeyFilePrimaryMasterKeyKey = @"primaryMasterKey";
NSString *const kSETOMasterKeyFileMacMasterKeyKey = @"hmacMasterKey";

uint64_t const kSETOMasterKeyFileDefaultScryptCostParam = 32768; // 2^15
int const kSETOMasterKeyFileDefaultScryptSaltSize = 8;
uint32_t const kSETOMasterKeyFileDefaultScryptBlockSize = 8;

@interface SETOMasterKeyFile ()
@property (nonatomic, assign) uint32_t version;
@property (nonatomic, strong) NSData *scryptSalt;
@property (nonatomic, assign) uint64_t scryptCostParam;
@property (nonatomic, assign) uint32_t scryptBlockSize;
@property (nonatomic, strong) NSData *primaryMasterKey;
@property (nonatomic, strong) NSData *macMasterKey;
@property (nonatomic, strong) NSData *versionMac;
@end

@implementation SETOMasterKeyFile

- (instancetype)initWithContentFromJSONData:(NSData *)jsonData {
	NSParameterAssert(jsonData);
	if (self = [super init]) {
		NSError *error;
		NSDictionary *jsonDict = [NSJSONSerialization JSONObjectWithData:jsonData options:0 error:&error];
		if (error) {
			return nil;
		} else {
			if (![KZPropertyMapper mapValuesFrom:jsonDict toInstance:self usingMapping:@{
				kSETOMasterKeyFileVersionKey: KZProperty(version),
				kSETOMasterKeyFileScryptSaltKey: KZCall(dataFromBase64EncodedString:, scryptSalt),
				kSETOMasterKeyFileScryptCostParamKey: KZProperty(scryptCostParam),
				kSETOMasterKeyFileScryptBlockSizeKey: KZProperty(scryptBlockSize),
				kSETOMasterKeyFilePrimaryMasterKeyKey: KZCall(dataFromBase64EncodedString:, primaryMasterKey),
				kSETOMasterKeyFileMacMasterKeyKey: KZCall(dataFromBase64EncodedString:, macMasterKey),
				kSETOMasterKeyFileVersionMacKey: KZCall(dataFromBase64EncodedString:, versionMac)
			}]) {
				return nil;
			}
		}
	}
	return self;
}

- (SETOMasterKey *)unlockWithPassphrase:(NSString *)passphrase pepper:(NSData *)pepper expectedVaultVersion:(NSInteger)expectedVaultVersion error:(NSError **)error {
	NSParameterAssert(passphrase);
	if (!self.primaryMasterKey || !self.macMasterKey) {
		if (error) {
			*error = [NSError errorWithDomain:kSETOMasterKeyFileErrorDomain code:SETOMasterKeyFileMalformedError userInfo:nil];
		}
		return nil;
	}

	// add pepper bytes to scrypt salt:
	unsigned char saltAndPepperBuffer[self.scryptSalt.length + pepper.length];
	memcpy(&saltAndPepperBuffer[0], self.scryptSalt.bytes, self.scryptSalt.length);
	memcpy(&saltAndPepperBuffer[8], pepper.bytes, pepper.length);
	NSData *saltAndPepper = [NSData dataWithBytes:saltAndPepperBuffer length:sizeof(saltAndPepperBuffer)];

	// scrypt key derivation:
	NSData *passphraseData;
	if (self.version >= 6) {
		// beginning with vault version 6, password is normalized to NFC:
		passphraseData = [[passphrase precomposedStringWithCanonicalMapping] dataUsingEncoding:NSUTF8StringEncoding];
	} else {
		passphraseData = [passphrase dataUsingEncoding:NSUTF8StringEncoding];
	}
	uint64_t costParam = self.scryptCostParam;
	uint32_t blockSize = (uint32_t)self.scryptBlockSize;
	unsigned char kekBytes[kCCKeySizeAES256];
	if (crypto_scrypt(passphraseData.bytes, passphraseData.length, saltAndPepper.bytes, saltAndPepper.length, costParam, blockSize, 1, kekBytes, sizeof(kekBytes)) == -1) {
		if (error) {
			*error = [NSError errorWithDomain:kSETOMasterKeyFileErrorDomain code:SETOMasterKeyFileKeyDerivationFailedError userInfo:nil];
		}
		return nil;
	}

	// unwrap primary and mac master keys:
	NSError *keyWrapError;
	NSData *primaryMasterKey = [SETOMasterKeyFile unwrapKey:self.primaryMasterKey kek:kekBytes error:&keyWrapError];
	if (keyWrapError) {
		if (error) {
			*error = keyWrapError;
		}
		return nil;
	}
	NSData *macMasterKey = [SETOMasterKeyFile unwrapKey:self.macMasterKey kek:kekBytes error:&keyWrapError];
	if (keyWrapError) {
		if (error) {
			*error = keyWrapError;
		}
		return nil;
	}

	// check MAC:
	BOOL versionMacsEqual = YES;
	if (self.version >= 5 && expectedVaultVersion != NSNotFound) {
		// calculate mac over version:
		unsigned char version[sizeof(uint32_t)] = {0};
		int_to_big_endian_bytes((uint32_t)expectedVaultVersion, version);
		unsigned char calculatedVersionMac[CC_SHA256_DIGEST_LENGTH];
		CCHmacContext versionHmacContext;
		CCHmacInit(&versionHmacContext, kCCHmacAlgSHA256, macMasterKey.bytes, macMasterKey.length);
		CCHmacUpdate(&versionHmacContext, version, sizeof(int32_t));
		CCHmacFinal(&versionHmacContext, calculatedVersionMac);

		// constant time comparison of version mac:
		unsigned char *expectedVersionMac = (unsigned char *)self.versionMac.bytes;
		versionMacsEqual = compare_bytes(calculatedVersionMac, expectedVersionMac, CC_SHA256_DIGEST_LENGTH);
	}

	// done:
	if (versionMacsEqual) {
		return [[SETOMasterKey alloc] initWithAESMasterKey:primaryMasterKey macMasterkey:macMasterKey];
	} else {
		if (error) {
			*error = [NSError errorWithDomain:kSETOMasterKeyFileErrorDomain code:SETOMasterKeyFileMalformedError userInfo:nil];
		}
		return nil;
	}
}

+ (NSData *)lockMasterKey:(SETOMasterKey *)masterKey withVaultVersion:(NSInteger)vaultVersion passphrase:(NSString *)passphrase pepper:(NSData *)pepper scryptCostParam:(uint64_t)scryptCostParam error:(NSError **)error {
	return [SETOMasterKeyFile lockMasterKey:masterKey withVaultVersion:vaultVersion passphrase:passphrase pepper:pepper scryptCostParam:scryptCostParam secureRandom:[SETOSecureRandom sharedInstance] error:error];
}

+ (NSData *)lockMasterKey:(SETOMasterKey *)masterKey withVaultVersion:(NSInteger)vaultVersion passphrase:(NSString *)passphrase pepper:(NSData *)pepper scryptCostParam:(uint64_t)scryptCostParam secureRandom:(SETOSecureRandom *)secureRandom error:(NSError **)error {
	NSParameterAssert(masterKey);
	NSParameterAssert(passphrase);
	if ([NSThread isMainThread]) {
		NSLog(@"Warning: +[SETOMasterKeyFile lockMasterKey:withVaultVersion:passphrase:pepper:error:] should be called from a background thread, as random number generation will benefit from UI interaction.");
	}
	if (!masterKey.aesMasterKey || !masterKey.macMasterKey) {
		if (error) {
			*error = [NSError errorWithDomain:kSETOMasterKeyFileErrorDomain code:SETOMasterKeyFileMalformedError userInfo:nil];
		}
		return nil;
	}

	// create random bytes for scrypt salt:
	NSError *secureRandomError;
	NSData *salt = [secureRandom generateDataWithSize:kSETOMasterKeyFileDefaultScryptSaltSize error:&secureRandomError];
	if (secureRandomError) {
		if (error) {
			*error = secureRandomError;
		}
		return nil;
	}

	// add pepper bytes to scrypt salt:
	unsigned char saltAndPepperBuffer[salt.length + pepper.length];
	memcpy(&saltAndPepperBuffer[0], salt.bytes, salt.length);
	memcpy(&saltAndPepperBuffer[8], pepper.bytes, pepper.length);
	NSData *saltAndPepper = [NSData dataWithBytes:saltAndPepperBuffer length:sizeof(saltAndPepperBuffer)];

	// scrypt key derivation:
	NSData *passphraseData;
	if (vaultVersion >= 6) {
		// beginning with vault version 6, password is normalized to NFC:
		passphraseData = [[passphrase precomposedStringWithCanonicalMapping] dataUsingEncoding:NSUTF8StringEncoding];
	} else {
		passphraseData = [passphrase dataUsingEncoding:NSUTF8StringEncoding];
	}
	unsigned char kekBytes[kCCKeySizeAES256];
	if (crypto_scrypt(passphraseData.bytes, passphraseData.length, saltAndPepper.bytes, saltAndPepper.length, scryptCostParam, kSETOMasterKeyFileDefaultScryptBlockSize, 1, kekBytes, sizeof(kekBytes)) == -1) {
		if (error) {
			*error = [NSError errorWithDomain:kSETOMasterKeyFileErrorDomain code:SETOMasterKeyFileKeyDerivationFailedError userInfo:nil];
		}
		return nil;
	}

	// wrap primary and mac master keys:
	NSError *keyWrapError;
	NSData *wrappedPrimaryMasterKey = [SETOMasterKeyFile wrapKey:masterKey.aesMasterKey kek:kekBytes error:&keyWrapError];
	if (keyWrapError) {
		if (error) {
			*error = keyWrapError;
		}
		return nil;
	}
	NSData *wrappedMacMasterKey = [SETOMasterKeyFile wrapKey:masterKey.macMasterKey kek:kekBytes error:&keyWrapError];
	if (keyWrapError) {
		if (error) {
			*error = keyWrapError;
		}
		return nil;
	}

	// calculate mac over version:
	unsigned char versionMac[CC_SHA256_DIGEST_LENGTH];
	unsigned char versionBytes[sizeof(uint32_t)] = {0};
	int_to_big_endian_bytes((uint32_t)vaultVersion, versionBytes);
	CCHmacContext versionHmacContext;
	CCHmacInit(&versionHmacContext, kCCHmacAlgSHA256, masterKey.macMasterKey.bytes, (size_t)masterKey.macMasterKey.length);
	CCHmacUpdate(&versionHmacContext, versionBytes, sizeof(versionBytes));
	CCHmacFinal(&versionHmacContext, &versionMac);

	// master key file assembly:
	SETOMasterKeyFile *masterKeyFile = [[SETOMasterKeyFile alloc] init];
	masterKeyFile.version = (uint32_t)vaultVersion;
	masterKeyFile.scryptSalt = salt;
	masterKeyFile.scryptCostParam = scryptCostParam;
	masterKeyFile.scryptBlockSize = kSETOMasterKeyFileDefaultScryptBlockSize;
	masterKeyFile.primaryMasterKey = wrappedPrimaryMasterKey;
	masterKeyFile.macMasterKey = wrappedMacMasterKey;
	masterKeyFile.versionMac = [NSData dataWithBytes:versionMac length:sizeof(versionMac)];

	// convert to json data:
	NSError *jsonWritingError;
	NSData *jsonData = [NSJSONSerialization dataWithJSONObject:masterKeyFile.dictionaryRepresentation options:NSJSONWritingPrettyPrinted error:&jsonWritingError];
	if (jsonWritingError) {
		if (error) {
			*error = jsonWritingError;
		}
		return nil;
	}
	return jsonData;
}

#pragma mark - RFC 3394 Key Wrap

+ (NSData *)wrapKey:(NSData *)rawKey kek:(unsigned char *)kekBytes error:(NSError **)error {
	NSParameterAssert(rawKey);
	const EVP_CIPHER *cipher = EVP_aes_256_ecb();
	EVP_CIPHER_CTX ctx;
	EVP_CIPHER_CTX_init(&ctx);
	EVP_EncryptInit_ex(&ctx, cipher, NULL, kekBytes, NULL);
	unsigned char wrappedKeyBuffer[kCCKeySizeAES256 + 8];
	int wrappedKeyLength = EVP_aes_wrap_key(&ctx, NULL, wrappedKeyBuffer, rawKey.bytes, (unsigned int)rawKey.length);
	EVP_CIPHER_CTX_cleanup(&ctx);
	if (wrappedKeyLength == -1) {
		if (error) {
			*error = [NSError errorWithDomain:kSETOMasterKeyFileErrorDomain code:SETOMasterKeyFileKeyWrapFailedError userInfo:nil];
		}
		return nil;
	} else {
		return [NSData dataWithBytes:wrappedKeyBuffer length:sizeof(wrappedKeyBuffer)];
	}
}

+ (NSData *)unwrapKey:(NSData *)wrappedKey kek:(unsigned char *)kekBytes error:(NSError **)error {
	NSParameterAssert(wrappedKey);
	const EVP_CIPHER *cipher = EVP_aes_256_ecb();
	EVP_CIPHER_CTX ctx;
	EVP_CIPHER_CTX_init(&ctx);
	EVP_DecryptInit_ex(&ctx, cipher, NULL, kekBytes, NULL);
	unsigned char unwrappedKeyBuffer[kCCKeySizeAES256];
	int unwrappedKeyLength = EVP_aes_unwrap_key(&ctx, NULL, unwrappedKeyBuffer, wrappedKey.bytes, (unsigned int)wrappedKey.length);
	EVP_CIPHER_CTX_cleanup(&ctx);
	if (unwrappedKeyLength == -1) {
		if (error) {
			*error = [NSError errorWithDomain:kSETOMasterKeyFileErrorDomain code:SETOMasterKeyFileKeyWrapFailedError userInfo:nil];
		}
		return nil;
	} else if (unwrappedKeyLength == 0) {
		if (error) {
			*error = [NSError errorWithDomain:kSETOMasterKeyFileErrorDomain code:SETOMasterKeyFileInvalidPassphraseError userInfo:nil];
		}
		return nil;
	} else {
		return [NSData dataWithBytes:unwrappedKeyBuffer length:sizeof(unwrappedKeyBuffer)];
	}
}

#pragma mark - Convenience

- (NSDictionary *)dictionaryRepresentation {
	return @{
		kSETOMasterKeyFileVersionKey: @(self.version),
		kSETOMasterKeyFileVersionMacKey: [self.versionMac base64EncodedStringWithOptions:0],
		kSETOMasterKeyFileScryptSaltKey: [self.scryptSalt base64EncodedStringWithOptions:0],
		kSETOMasterKeyFileScryptCostParamKey: @(self.scryptCostParam),
		kSETOMasterKeyFileScryptBlockSizeKey: @(self.scryptBlockSize),
		kSETOMasterKeyFilePrimaryMasterKeyKey: [self.primaryMasterKey base64EncodedStringWithOptions:0],
		kSETOMasterKeyFileMacMasterKeyKey: [self.macMasterKey base64EncodedStringWithOptions:0]
	};
}

- (NSData *)dataFromBase64EncodedString:(NSString *)base64EncodedString {
	return [[NSData alloc] initWithBase64EncodedString:base64EncodedString options:0];
}

@end
