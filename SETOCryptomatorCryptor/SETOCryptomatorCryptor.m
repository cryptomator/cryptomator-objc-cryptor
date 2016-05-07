//
//  SETOCryptomatorCryptor.m
//  SETOCryptomatorCryptor
//
//  Created by Sebastian Stenzel on 14/02/15.
//  Copyright © 2015-2016 setoLabs. All rights reserved.
//

#import "SETOCryptomatorCryptor.h"
#import "SETOAesSivCipherUtil.h"
#import "SETOCryptoSupport.h"
#import "SETOMasterKey.h"
#import "NSString+SETOBase32Validation.h"

#import <CommonCrypto/CommonCryptor.h>
#import <CommonCrypto/CommonDigest.h>
#import <CommonCrypto/CommonHMAC.h>
#import <Security/Security.h>
#import <Base32/MF_Base32Additions.h>
#import <openssl/evp.h>
#import "e_aeswrap.h"
#import "crypto_scrypt.h"

// exposing SETOMasterKey's properties for direct mutation
@interface SETOMasterKey ()
@property (nonatomic, assign) uint32_t version;
@property (nonatomic, strong) NSData *versionMac;
@property (nonatomic, strong) NSData *scryptSalt;
@property (nonatomic, assign) uint64_t scryptCostParam;
@property (nonatomic, assign) uint32_t scryptBlockSize;
@property (nonatomic, strong) NSData *primaryMasterKey;
@property (nonatomic, strong) NSData *macMasterKey;
@end

#pragma mark -

NSString *const kSETOCryptomatorCryptorErrorDomain = @"SETOCryptomatorCryptorErrorDomain";

int const kSETOCryptomatorCryptorKeyLength = 256;
int const kSETOCryptomatorCryptorNonceLength = 16;
int const kSETOCryptomatorCryptorHeaderLength = 88;
int const kSETOCryptomatorCryptorHeaderPayloadLength = 40;
int const kSETOCryptomatorCryptorChunkPayloadLength = 32 * 1024;

@interface SETOCryptomatorCryptor ()
@property (nonatomic, strong) SETOMasterKey *masterKey;
@property (nonatomic, copy) NSData *primaryMasterKey;
@property (nonatomic, copy) NSData *macMasterKey;
@end

@implementation SETOCryptomatorCryptor

static const size_t BLOCK_SIZE = 16;

#pragma mark - Initialization and Unlocking

+ (SETOMasterKey *)newMasterKeyForPassword:(NSString *)password {
	if ([NSThread isMainThread]) {
		NSLog(@"Warning: This method should be called from a background thread, as random number generation will benefit from UI interaction.");
	}

	unsigned char scryptSaltBuffer[8];
	if (SecRandomCopyBytes(kSecRandomDefault, sizeof(scryptSaltBuffer), scryptSaltBuffer) == -1) {
		NSLog(@"Unable to create random bytes for scryptSaltBuffer.");
		return nil;
	}

	unsigned char primaryMasterKeyBuffer[32];
	if (SecRandomCopyBytes(kSecRandomDefault, sizeof(primaryMasterKeyBuffer), primaryMasterKeyBuffer) == -1) {
		NSLog(@"Unable to create random bytes for primaryMasterKeyBuffer.");
		return nil;
	}

	unsigned char macMasterKeyBuffer[32];
	if (SecRandomCopyBytes(kSecRandomDefault, sizeof(macMasterKeyBuffer), macMasterKeyBuffer) == -1) {
		NSLog(@"Unable to create random bytes for macMasterKeyBuffer.");
		return nil;
	}

	// scrypt key derivation:
	NSData *passwordData = [password dataUsingEncoding:NSUTF8StringEncoding];
	NSData *scryptSalt = [NSData dataWithBytes:scryptSaltBuffer length:sizeof(scryptSaltBuffer)];
	uint64_t costParam = 16384;
	uint32_t blockSize = 8;
	unsigned char kekBytes[kSETOCryptomatorCryptorKeyLength / 8];
	crypto_scrypt(passwordData.bytes, passwordData.length, scryptSalt.bytes, scryptSalt.length, costParam, blockSize, 1, kekBytes, sizeof(kekBytes));

	// key wrapping:
	const EVP_CIPHER *cipher = EVP_aes_256_ecb();
	EVP_CIPHER_CTX ctx;
	EVP_CIPHER_CTX_init(&ctx);
	EVP_EncryptInit_ex(&ctx, cipher, NULL, kekBytes, NULL);
	unsigned char wrappedPrimaryMasterKeyBuffer[kSETOCryptomatorCryptorKeyLength / 8 + 8];
	EVP_aes_wrap_key(&ctx, NULL, wrappedPrimaryMasterKeyBuffer, primaryMasterKeyBuffer, sizeof(primaryMasterKeyBuffer));
	NSData *wrappedPrimaryMasterKey = [NSData dataWithBytes:wrappedPrimaryMasterKeyBuffer length:sizeof(wrappedPrimaryMasterKeyBuffer)];
	unsigned char wrappedMacMasterKeyBuffer[kSETOCryptomatorCryptorKeyLength / 8 + 8];
	EVP_aes_wrap_key(&ctx, NULL, wrappedMacMasterKeyBuffer, macMasterKeyBuffer, sizeof(macMasterKeyBuffer));
	NSData *wrappedMacMasterKey = [NSData dataWithBytes:wrappedMacMasterKeyBuffer length:sizeof(wrappedMacMasterKeyBuffer)];
	EVP_CIPHER_CTX_cleanup(&ctx);

	// calculate mac over version:
	unsigned char versionMac[CC_SHA256_DIGEST_LENGTH];
	unsigned char versionBytes[sizeof(uint32_t)] = {0};
	int_to_big_endian_bytes(kSETOMasterKeyCurrentVersion, versionBytes);
	CCHmacContext versionHmacContext;
	CCHmacInit(&versionHmacContext, kCCHmacAlgSHA256, macMasterKeyBuffer, sizeof(macMasterKeyBuffer));
	CCHmacUpdate(&versionHmacContext, versionBytes, 0);
	CCHmacFinal(&versionHmacContext, &versionMac);

	// masterkey assembly:
	SETOMasterKey *masterKey = [[SETOMasterKey alloc] init];
	masterKey.version = kSETOMasterKeyCurrentVersion;
	masterKey.versionMac = [NSData dataWithBytes:versionMac length:sizeof(versionMac)];
	masterKey.scryptSalt = scryptSalt;
	masterKey.scryptCostParam = costParam;
	masterKey.scryptBlockSize = blockSize;
	masterKey.primaryMasterKey = wrappedPrimaryMasterKey;
	masterKey.macMasterKey = wrappedMacMasterKey;

	return masterKey;
}

- (instancetype)initWithMasterKey:(SETOMasterKey *)masterKey {
	NSParameterAssert(masterKey);
	if (self = [super init]) {
		self.masterKey = masterKey;
	}
	return self;
}

- (SETOCryptomatorCryptorUnlockResult)unlockWithPassword:(NSString *)password {
	NSParameterAssert(password);

	if (self.masterKey.version != kSETOMasterKeyCurrentVersion) {
		return SETOCryptomatorCryptorUnlockVersionMismatch;
	}

	// scrypt key derivation:
	NSData *passwordData = [password dataUsingEncoding:NSUTF8StringEncoding];
	NSData *scryptSalt = self.masterKey.scryptSalt;
	uint64_t costParam = self.masterKey.scryptCostParam;
	uint32_t blockSize = (uint32_t)self.masterKey.scryptBlockSize;
	unsigned char kekBytes[kSETOCryptomatorCryptorKeyLength / 8];
	crypto_scrypt(passwordData.bytes, passwordData.length, scryptSalt.bytes, scryptSalt.length, costParam, blockSize, 1, kekBytes, sizeof(kekBytes));

	// unwrap primary and mac master keys:
	const EVP_CIPHER *cipher = EVP_aes_256_ecb();
	EVP_CIPHER_CTX ctx;
	EVP_CIPHER_CTX_init(&ctx);
	EVP_DecryptInit_ex(&ctx, cipher, NULL, kekBytes, NULL);

	NSData *wrappedPrimaryMasterKey = self.masterKey.primaryMasterKey;
	unsigned char unwrappedPrimaryMasterKeyBuffer[kSETOCryptomatorCryptorKeyLength / 8];
	int unwrappedPrimaryMasterKeyLength = EVP_aes_unwrap_key(&ctx, NULL, unwrappedPrimaryMasterKeyBuffer, wrappedPrimaryMasterKey.bytes, (int)wrappedPrimaryMasterKey.length);

	NSData *wrappedMacMasterKey = self.masterKey.macMasterKey;
	unsigned char unwrappedMacMasterKeyBuffer[kSETOCryptomatorCryptorKeyLength / 8];
	int unwrappedMacMasterKeyLength = EVP_aes_unwrap_key(&ctx, NULL, unwrappedMacMasterKeyBuffer, wrappedMacMasterKey.bytes, (int)wrappedMacMasterKey.length);

	EVP_CIPHER_CTX_cleanup(&ctx);

	// check for key lengths, zero length means password is wrong:
	if (unwrappedPrimaryMasterKeyLength == 0 || unwrappedMacMasterKeyLength == 0) {
		return SETOCryptomatorCryptorUnlockWrongPassword;
	}

	// initialize master keys:
	self.primaryMasterKey = [NSData dataWithBytes:unwrappedPrimaryMasterKeyBuffer length:unwrappedPrimaryMasterKeyLength];
	self.macMasterKey = [NSData dataWithBytes:unwrappedMacMasterKeyBuffer length:unwrappedMacMasterKeyLength];

	// clean up:
	for (int i = 0; i < unwrappedPrimaryMasterKeyLength; i++) {
		unwrappedPrimaryMasterKeyBuffer[i] = 0;
	}
	for (int i = 0; i < unwrappedMacMasterKeyLength; i++) {
		unwrappedMacMasterKeyBuffer[i] = 0;
	}

	// done:
	return SETOCryptomatorCryptorUnlockSuccess;
}

- (BOOL)isUnlocked {
	return self.primaryMasterKey && self.macMasterKey;
}

#pragma mark - Path Encryption and Decryption

- (NSString *)encryptDirectoryId:(NSString *)directoryId {
	if (![self isUnlocked]) {
		NSLog(@"Unable to encrypt directory id: Unlock this cryptor by using unlockWithPassword: first.");
		return nil;
	}

	NSParameterAssert(directoryId);
	NSData *plaintext = [directoryId dataUsingEncoding:NSUTF8StringEncoding];
	unsigned char *ciphertext = malloc(plaintext.length + 16);
	if (siv_enc(self.primaryMasterKey.bytes, self.macMasterKey.bytes, self.primaryMasterKey.length, plaintext.bytes, plaintext.length, 0, NULL, NULL, ciphertext)) {
		free(ciphertext);
		return nil;
	}
	unsigned char hashed[CC_SHA1_DIGEST_LENGTH];
	CC_SHA1(ciphertext, (CC_LONG)plaintext.length + 16, hashed);
	free(ciphertext);
	NSData *ciphertextData = [NSData dataWithBytes:hashed length:CC_SHA1_DIGEST_LENGTH];
	return [ciphertextData base32String];
}

- (NSString *)encryptFilename:(NSString *)filename insideDirectoryWithId:(NSString *)directoryId {
	if (![self isUnlocked]) {
		NSLog(@"Unable to encrypt filename: Unlock this cryptor by using unlockWithPassword: first.");
		return nil;
	}

	NSParameterAssert(filename);
	NSString *normalizedFilename = [filename precomposedStringWithCanonicalMapping];
	NSData *plaintext = [normalizedFilename dataUsingEncoding:NSUTF8StringEncoding];
	unsigned char *ciphertext = malloc(plaintext.length + 16);
	NSData *directoryIdData = [directoryId dataUsingEncoding:NSUTF8StringEncoding];
	const unsigned char *additionalData[1] = {directoryIdData.bytes};
	const size_t additionalDataSizes[1] = {directoryIdData.length};
	if (siv_enc(self.primaryMasterKey.bytes, self.macMasterKey.bytes, self.primaryMasterKey.length, plaintext.bytes, plaintext.length, 1, additionalData, additionalDataSizes, ciphertext)) {
		free(ciphertext);
		return nil;
	}
	NSData *ciphertextData = [NSData dataWithBytesNoCopy:ciphertext length:plaintext.length + 16];
	return [ciphertextData base32String];
}

- (NSString *)decryptFilename:(NSString *)filename insideDirectoryWithId:(NSString *)directoryId {
	if (![self isUnlocked]) {
		NSLog(@"Unable to decrypt filename: Unlock this cryptor by using unlockWithPassword: first.");
		return nil;
	}

	NSParameterAssert(filename);
	if (!filename.seto_isValidBase32Encoded) {
		return nil;
	}
	NSData *ciphertext = [NSData dataWithBase32String:filename];
	if (!ciphertext) {
		return nil;
	}
	unsigned char *plaintext = malloc(ciphertext.length - 16);
	NSData *directoryIdData = [directoryId dataUsingEncoding:NSUTF8StringEncoding];
	const unsigned char *additionalData[1] = {directoryIdData.bytes};
	const size_t additionalDataSizes[1] = {directoryIdData.length};
	if (siv_dec(self.primaryMasterKey.bytes, self.macMasterKey.bytes, self.primaryMasterKey.length, ciphertext.bytes, ciphertext.length, 1, additionalData, additionalDataSizes, plaintext)) {
		free(plaintext);
		return nil;
	}
	NSData *plaintextData = [NSData dataWithBytesNoCopy:plaintext length:ciphertext.length - 16];
	return [[NSString alloc] initWithData:plaintextData encoding:NSUTF8StringEncoding];
}

#pragma mark - File Content Encryption and Decryption

- (void)authenticateFileAtPath:(NSString *)path callback:(SETOCryptomatorCryptorCompletionCallback)callback progress:(SETOCryptomatorCryptorProgressCallback)progressCallback {
	if (![self isUnlocked]) {
		NSLog(@"Unable to authenticate file: Unlock this cryptor by using unlockWithPassword: first.");
		return;
	}

	NSParameterAssert(path);
	NSParameterAssert(callback);

	// read ciphertext file size:
	NSError *fileAttributesError;
	NSDictionary *fileAttributes = [[NSFileManager defaultManager] attributesOfItemAtPath:path error:&fileAttributesError];
	if (fileAttributesError) {
		callback(fileAttributesError);
		return;
	}
	uint64_t totalFileSize = [fileAttributes fileSize];

	// init progress:
	uint64_t bytesProcessed = 0;
	if (progressCallback) {
		progressCallback(0.0);
	}

	// open ciphertext input:
	NSInputStream *input = [NSInputStream inputStreamWithFileAtPath:path];
	[input scheduleInRunLoop:[NSRunLoop currentRunLoop] forMode:NSDefaultRunLoopMode];
	[input open];

	// read file header:
	unsigned char header[kSETOCryptomatorCryptorHeaderLength];
	int inputLength = (int)[input read:header maxLength:sizeof(header)];
	if (inputLength != sizeof(header)) {
		[input close];
		callback([NSError errorWithDomain:kSETOCryptomatorCryptorErrorDomain code:SETOCryptomatorCryptorCorruptedFileHeaderError userInfo:nil]);
		return;
	}
	bytesProcessed += inputLength;

	// iv is at the beginning of file header:
	unsigned char *iv = &header[0];

	// calculate mac over file header:
	unsigned char calculatedHeaderMac[CC_SHA256_DIGEST_LENGTH];
	CCHmacContext headerHmacContext;
	CCHmacInit(&headerHmacContext, kCCHmacAlgSHA256, self.macMasterKey.bytes, self.macMasterKey.length);
	CCHmacUpdate(&headerHmacContext, header, 56); // 56 bytes: 16 bytes iv + 8 bytes file size + 32 bytes file key (without mac)
	CCHmacFinal(&headerHmacContext, calculatedHeaderMac);

	// calculate macs over file chunks:
	BOOL chunkMacsEqual = YES;
	uint64_t chunkNumber = 0;
	int ciphertextChunkLength = kSETOCryptomatorCryptorNonceLength + kSETOCryptomatorCryptorChunkPayloadLength + CC_SHA256_DIGEST_LENGTH; // nonce + payload + mac
	NSMutableData *ciphertextChunk = [NSMutableData dataWithLength:ciphertextChunkLength];
	while (input.hasBytesAvailable) {
		// read chunk:
		unsigned char *ciphertextChunkBuffer = ciphertextChunk.mutableBytes;
		int inputLength = (int)[input read:ciphertextChunkBuffer maxLength:ciphertextChunkLength];
		if (inputLength == 0) {
			continue;
		} else if (inputLength < kSETOCryptomatorCryptorNonceLength + CC_SHA256_DIGEST_LENGTH) {
			[input close];
			callback([NSError errorWithDomain:kSETOCryptomatorCryptorErrorDomain code:SETOCryptomatorCryptorAuthenticationFailedError userInfo:nil]);
			return;
		}

		// init authentication:
		unsigned char *expectedMac = &ciphertextChunkBuffer[inputLength - CC_SHA256_DIGEST_LENGTH];
		unsigned char calculatedMac[CC_SHA256_DIGEST_LENGTH];
		unsigned char chunkNumberBytes[sizeof(uint64_t)] = {0};
		unsigned char *nonce = &ciphertextChunkBuffer[0];
		unsigned char *payload = &ciphertextChunkBuffer[kSETOCryptomatorCryptorNonceLength];
		int payloadLength = inputLength - kSETOCryptomatorCryptorNonceLength - CC_SHA256_DIGEST_LENGTH;
		long_to_big_endian_bytes(chunkNumber, chunkNumberBytes);

		// calculate chunk mac:
		CCHmacContext chunkHmacContext;
		CCHmacInit(&chunkHmacContext, kCCHmacAlgSHA256, self.macMasterKey.bytes, self.macMasterKey.length);
		CCHmacUpdate(&chunkHmacContext, iv, 16);
		CCHmacUpdate(&chunkHmacContext, chunkNumberBytes, sizeof(chunkNumberBytes));
		CCHmacUpdate(&chunkHmacContext, nonce, kSETOCryptomatorCryptorNonceLength);
		CCHmacUpdate(&chunkHmacContext, payload, payloadLength);
		CCHmacFinal(&chunkHmacContext, calculatedMac);

		// constant time comparison of chunk mac:
		for (int i = 0; i < CC_SHA256_DIGEST_LENGTH; i++) {
			chunkMacsEqual &= areBytesEqual(calculatedMac[i], expectedMac[i]);
		}

		// progress:
		bytesProcessed += inputLength;
		chunkNumber++;
		if (progressCallback) {
			progressCallback((CGFloat)bytesProcessed / totalFileSize);
		}
	}

	// constant time comparison of header mac:
	unsigned char *expectedHeaderMac = &header[56];
	BOOL headerMacsEqual = YES;
	for (int i = 0; i < CC_SHA256_DIGEST_LENGTH; i++) {
		headerMacsEqual &= areBytesEqual(calculatedHeaderMac[i], expectedHeaderMac[i]);
	}

	// done:
	[input close];
	if (progressCallback) {
		progressCallback(1.0);
	}
	callback(headerMacsEqual && chunkMacsEqual ? nil : [NSError errorWithDomain:kSETOCryptomatorCryptorErrorDomain code:SETOCryptomatorCryptorAuthenticationFailedError userInfo:nil]);
}

- (void)encryptFileAtPath:(NSString *)inPath toPath:(NSString *)outPath callback:(SETOCryptomatorCryptorCompletionCallback)callback progress:(SETOCryptomatorCryptorProgressCallback)progressCallback {
	if (![self isUnlocked]) {
		NSLog(@"Unable to encrypt file: Unlock this cryptor by using unlockWithPassword: first.");
		return;
	}

	NSParameterAssert(inPath);
	NSParameterAssert(outPath);
	NSParameterAssert(callback);

	// read plaintext file size:
	NSError *filesAttributesError;
	NSDictionary *fileAttributes = [[NSFileManager defaultManager] attributesOfItemAtPath:inPath error:&filesAttributesError];
	if (filesAttributesError) {
		callback(filesAttributesError);
		return;
	}
	uint64_t fileSize = [fileAttributes fileSize];

	// determine length of random padding:
	uint32_t maxPaddingLength = (uint32_t)MIN(MAX(fileSize / 10, 4096), 16 * 1024 * 1024);
	uint32_t randomPaddingLength = arc4random_uniform(maxPaddingLength);

	// init progress:
	uint64_t bytesTotal = fileSize + randomPaddingLength; // include random padding
	uint64_t bytesProcessed = 0;
	if (progressCallback) {
		progressCallback(0.0);
	}

	// allocate file header buffer:
	unsigned char header[kSETOCryptomatorCryptorHeaderLength];

	// create random iv:
	if (SecRandomCopyBytes(kSecRandomDefault, 16, header) == -1) {
		callback([NSError errorWithDomain:kSETOCryptomatorCryptorErrorDomain code:SETOCryptomatorCryptorEncryptionFailedError userInfo:nil]);
		return;
	}
	unsigned char *iv = &header[0];
	unsigned char *ciphertextHeaderPayload = &header[16];

	// create random file key:
	unsigned char fileKey[32];
	if (SecRandomCopyBytes(kSecRandomDefault, 32, fileKey) == -1) {
		callback([NSError errorWithDomain:kSETOCryptomatorCryptorErrorDomain code:SETOCryptomatorCryptorEncryptionFailedError userInfo:nil]);
		return;
	}

	// encrypt header data:
	unsigned char plaintextHeaderPayload[kSETOCryptomatorCryptorHeaderPayloadLength];
	long_to_big_endian_bytes(fileSize, plaintextHeaderPayload);
	memcpy(&plaintextHeaderPayload[8], fileKey, sizeof(fileKey));
	{
		const EVP_CIPHER *ctrCipher = EVP_aes_256_ctr();
		EVP_CIPHER_CTX ctx;
		EVP_CIPHER_CTX_init(&ctx);
		EVP_CIPHER_CTX_set_padding(&ctx, 0);
		EVP_EncryptInit_ex(&ctx, ctrCipher, NULL, self.primaryMasterKey.bytes, iv);
		int bytesEncrypted = 0;
		int encryptStatus = EVP_EncryptUpdate(&ctx, ciphertextHeaderPayload, &bytesEncrypted, plaintextHeaderPayload, kSETOCryptomatorCryptorHeaderPayloadLength);
		if (encryptStatus == 0 || bytesEncrypted != kSETOCryptomatorCryptorHeaderPayloadLength) {
			EVP_CIPHER_CTX_cleanup(&ctx);
			callback([NSError errorWithDomain:kSETOCryptomatorCryptorErrorDomain code:SETOCryptomatorCryptorEncryptionFailedError userInfo:nil]);
			return;
		}
		EVP_CIPHER_CTX_cleanup(&ctx);
	}

	// calculate mac over file header:
	CCHmacContext headerHmacContext;
	CCHmacInit(&headerHmacContext, kCCHmacAlgSHA256, self.macMasterKey.bytes, self.macMasterKey.length);
	CCHmacUpdate(&headerHmacContext, header, 56);
	CCHmacFinal(&headerHmacContext, &header[56]);

	// open plaintext input stream:
	NSInputStream *input = [NSInputStream inputStreamWithFileAtPath:inPath];
	[input scheduleInRunLoop:[NSRunLoop currentRunLoop] forMode:NSDefaultRunLoopMode];
	[input open];

	// open ciphertext output stream and write header:
	NSOutputStream *output = [NSOutputStream outputStreamToFileAtPath:outPath append:NO];
	[output scheduleInRunLoop:[NSRunLoop currentRunLoop] forMode:NSDefaultRunLoopMode];
	[output open];
	[output write:header maxLength:sizeof(header)];

	// encrypt then mac content + padding:
	const EVP_CIPHER *ctrCipher = EVP_aes_256_ctr();
	EVP_CIPHER_CTX ctx;
	EVP_CIPHER_CTX_init(&ctx);
	EVP_CIPHER_CTX_set_padding(&ctx, 0);
	uint64_t chunkNumber = 0;
	while (input.hasBytesAvailable && bytesProcessed < bytesTotal) {
		// read chunk:
		int plaintextChunkLength = kSETOCryptomatorCryptorChunkPayloadLength;
		unsigned char plaintextChunk[plaintextChunkLength];
		int inputLength = (int)[input read:plaintextChunk maxLength:plaintextChunkLength];
		if (inputLength == 0) {
			continue;
		} else if (inputLength < 0) {
			[input close];
			[output close];
			EVP_CIPHER_CTX_cleanup(&ctx);
			callback([NSError errorWithDomain:kSETOCryptomatorCryptorErrorDomain code:SETOCryptomatorCryptorEncryptionFailedError userInfo:nil]);
			return;
		}

		// add padding if necessary:
		uint64_t bytesRemaining = bytesTotal - bytesProcessed;
		int payloadLength = (int)MIN(bytesRemaining, kSETOCryptomatorCryptorChunkPayloadLength);
		int paddingLength = payloadLength - inputLength;
		arc4random_buf(&plaintextChunk[inputLength], paddingLength);
		inputLength += paddingLength;

		// init encryption:
		int ciphertextChunkLength = kSETOCryptomatorCryptorNonceLength + payloadLength + CC_SHA256_DIGEST_LENGTH;
		unsigned char ciphertextChunk[ciphertextChunkLength + BLOCK_SIZE];
		unsigned char *nonce = &ciphertextChunk[0];
		if (SecRandomCopyBytes(kSecRandomDefault, 16, nonce) == -1) {
			callback([NSError errorWithDomain:kSETOCryptomatorCryptorErrorDomain code:SETOCryptomatorCryptorEncryptionFailedError userInfo:nil]);
			return;
		}
		EVP_EncryptInit_ex(&ctx, ctrCipher, NULL, fileKey, nonce);

		// encrypt chunk:
		int bytesEncrypted;
		unsigned char *payload = &ciphertextChunk[16];
		int encryptStatus = EVP_EncryptUpdate(&ctx, payload, &bytesEncrypted, plaintextChunk, inputLength);
		if (encryptStatus == 0 || bytesEncrypted != payloadLength) {
			[input close];
			[output close];
			EVP_CIPHER_CTX_cleanup(&ctx);
			callback([NSError errorWithDomain:kSETOCryptomatorCryptorErrorDomain code:SETOCryptomatorCryptorEncryptionFailedError userInfo:nil]);
			return;
		}

		// authenticate ciphertext chunk:
		unsigned char *chunkMac = &ciphertextChunk[kSETOCryptomatorCryptorNonceLength + bytesEncrypted];
		unsigned char chunkNumberBytes[sizeof(uint64_t)] = {0};
		long_to_big_endian_bytes(chunkNumber, chunkNumberBytes);
		CCHmacContext chunkHmacContext;
		CCHmacInit(&chunkHmacContext, kCCHmacAlgSHA256, self.macMasterKey.bytes, self.macMasterKey.length);
		CCHmacUpdate(&chunkHmacContext, iv, 16);
		CCHmacUpdate(&chunkHmacContext, chunkNumberBytes, sizeof(chunkNumberBytes));
		CCHmacUpdate(&chunkHmacContext, nonce, 16);
		CCHmacUpdate(&chunkHmacContext, payload, bytesEncrypted);
		CCHmacFinal(&chunkHmacContext, chunkMac);

		// write ciphertext chunk:
		int bytesWritten = (int)[output write:ciphertextChunk maxLength:ciphertextChunkLength];
		if (bytesWritten != ciphertextChunkLength) {
			[input close];
			[output close];
			EVP_CIPHER_CTX_cleanup(&ctx);
			callback([NSError errorWithDomain:kSETOCryptomatorCryptorErrorDomain code:SETOCryptomatorCryptorEncryptionFailedError userInfo:nil]);
			return;
		}

		// progress:
		bytesProcessed += payloadLength;
		chunkNumber++;
		if (progressCallback) {
			progressCallback((CGFloat)bytesProcessed / bytesTotal);
		}
	}
	EVP_CIPHER_CTX_cleanup(&ctx);

	// done:
	[input close];
	[output close];
	if (progressCallback) {
		progressCallback(1.0);
	}
	callback(nil);
}

- (void)decryptFileAtPath:(NSString *)inPath toPath:(NSString *)outPath callback:(SETOCryptomatorCryptorCompletionCallback)callback progress:(SETOCryptomatorCryptorProgressCallback)progressCallback {
	if (![self isUnlocked]) {
		NSLog(@"Unable to decrypt file: Unlock this cryptor by using unlockWithPassword: first.");
		return;
	}

	NSParameterAssert(inPath);
	NSParameterAssert(outPath);
	NSParameterAssert(callback);

	// open ciphertext input stream:
	NSInputStream *input = [NSInputStream inputStreamWithFileAtPath:inPath];
	[input scheduleInRunLoop:[NSRunLoop currentRunLoop] forMode:NSDefaultRunLoopMode];
	[input open];

	// read file header:
	unsigned char header[kSETOCryptomatorCryptorHeaderLength];
	int inputLength = (int)[input read:header maxLength:sizeof(header)];
	if (inputLength != sizeof(header)) {
		[input close];
		callback([NSError errorWithDomain:kSETOCryptomatorCryptorErrorDomain code:SETOCryptomatorCryptorCorruptedFileHeaderError userInfo:nil]);
		return;
	}

	// iv is at the beginning of file header:
	unsigned char *iv = &header[0];
	unsigned char *ciphertextHeaderPayload = &header[16];

	// decrypt header data:
	unsigned char plaintextHeaderPayload[kSETOCryptomatorCryptorHeaderPayloadLength + BLOCK_SIZE];
	{
		const EVP_CIPHER *ctrCipher = EVP_aes_256_ctr();
		EVP_CIPHER_CTX ctx;
		EVP_CIPHER_CTX_init(&ctx);
		EVP_CIPHER_CTX_set_padding(&ctx, 0);
		EVP_DecryptInit_ex(&ctx, ctrCipher, NULL, self.primaryMasterKey.bytes, iv);
		int bytesDecrypted = 0;
		int decryptStatus = EVP_DecryptUpdate(&ctx, plaintextHeaderPayload, &bytesDecrypted, ciphertextHeaderPayload, kSETOCryptomatorCryptorHeaderPayloadLength);
		if (decryptStatus == 0 || bytesDecrypted != kSETOCryptomatorCryptorHeaderPayloadLength) {
			[input close];
			EVP_CIPHER_CTX_cleanup(&ctx);
			callback([NSError errorWithDomain:kSETOCryptomatorCryptorErrorDomain code:SETOCryptomatorCryptorCorruptedFileHeaderError userInfo:nil]);
			return;
		}
		EVP_CIPHER_CTX_cleanup(&ctx);
	}

	// extract file size and file key:
	uint64_t fileSize = big_endian_bytes_to_long(&plaintextHeaderPayload[0]);
	unsigned char *fileKey = &plaintextHeaderPayload[8];

	// initialize bytes processed:
	uint64_t bytesProcessed = 0;
	if (progressCallback) {
		progressCallback(0.0);
	}

	// open plaintext output stream:
	NSOutputStream *output = [NSOutputStream outputStreamToFileAtPath:outPath append:NO];
	[output scheduleInRunLoop:[NSRunLoop currentRunLoop] forMode:NSDefaultRunLoopMode];
	[output open];

	// decrypt content (ignoring chunk macs, assuming it's authentic):
	const EVP_CIPHER *ctrCipher = EVP_aes_256_ctr();
	EVP_CIPHER_CTX ctx;
	EVP_CIPHER_CTX_init(&ctx);
	EVP_CIPHER_CTX_set_padding(&ctx, 0);
	while (input.hasBytesAvailable && bytesProcessed < fileSize) {
		// read chunk:
		int ciphertextChunkLength = kSETOCryptomatorCryptorNonceLength + kSETOCryptomatorCryptorChunkPayloadLength + CC_SHA256_DIGEST_LENGTH;
		unsigned char ciphertextChunk[ciphertextChunkLength];
		int inputLength = (int)[input read:ciphertextChunk maxLength:ciphertextChunkLength];
		if (inputLength == 0) {
			continue;
		} else if (inputLength < kSETOCryptomatorCryptorNonceLength + CC_SHA256_DIGEST_LENGTH) {
			[input close];
			[output close];
			EVP_CIPHER_CTX_cleanup(&ctx);
			callback([NSError errorWithDomain:kSETOCryptomatorCryptorErrorDomain code:SETOCryptomatorCryptorDecryptionFailedError userInfo:nil]);
			return;
		}

		// init decryption:
		unsigned char *nonce = &ciphertextChunk[0];
		unsigned char *payload = &ciphertextChunk[kSETOCryptomatorCryptorNonceLength];
		EVP_DecryptInit_ex(&ctx, ctrCipher, NULL, fileKey, nonce);

		// calculate payload length:
		int payloadLength = inputLength - kSETOCryptomatorCryptorNonceLength - CC_SHA256_DIGEST_LENGTH;
		uint64_t remainingFileSize = fileSize - bytesProcessed;
		int remainingPayloadLength = payloadLength < remainingFileSize ? payloadLength : (int)remainingFileSize; // ignore padding if necessary

		// decrypt chunk:
		int plaintextChunkLength = payloadLength + BLOCK_SIZE;
		unsigned char plaintextChunk[plaintextChunkLength];
		int outputLength = 0;
		int decryptStatus = EVP_DecryptUpdate(&ctx, plaintextChunk, &outputLength, payload, remainingPayloadLength);
		if (decryptStatus == 0) {
			[input close];
			[output close];
			EVP_CIPHER_CTX_cleanup(&ctx);
			callback([NSError errorWithDomain:kSETOCryptomatorCryptorErrorDomain code:SETOCryptomatorCryptorDecryptionFailedError userInfo:nil]);
			return;
		}

		// write plaintext chunk:
		int bytesWritten = (int)[output write:plaintextChunk maxLength:outputLength];
		if (bytesWritten != outputLength) {
			[input close];
			[output close];
			EVP_CIPHER_CTX_cleanup(&ctx);
			callback([NSError errorWithDomain:kSETOCryptomatorCryptorErrorDomain code:SETOCryptomatorCryptorDecryptionFailedError userInfo:nil]);
			return;
		}

		// progress:
		bytesProcessed += payloadLength;
		if (progressCallback) {
			progressCallback((CGFloat)bytesProcessed / fileSize);
		}
	}
	EVP_CIPHER_CTX_cleanup(&ctx);

	// done:
	[input close];
	[output close];
	if (progressCallback) {
		progressCallback(1.0);
	}
	callback(nil);
}

@end
