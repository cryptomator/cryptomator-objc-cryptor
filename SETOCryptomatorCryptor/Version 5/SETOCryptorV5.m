//
//  SETOCryptorV5.m
//  SETOCryptomatorCryptor
//
//  Created by Tobias Hagemann on 02.09.16.
//  Copyright © 2015-2017 Skymatic. All rights reserved.
//

#import "SETOCryptorV5.h"
#import "SETOMasterKey.h"

#import "SETOCryptoSupport.h"

#import <CommonCrypto/CommonDigest.h>
#import <CommonCrypto/CommonHMAC.h>
#import <openssl/evp.h>

#pragma mark -

size_t const kSETOCryptorV5BlockSize = 16;
int const kSETOCryptorV5NonceLength = 16;
int const kSETOCryptorV5HeaderLength = 88;
int const kSETOCryptorV5HeaderPayloadLength = 40;
int const kSETOCryptorV5ChunkPayloadLength = 32 * 1024;

@interface SETOCryptorV5 ()
@property (nonatomic, strong) SETOMasterKey *masterKey;
@end

@implementation SETOCryptorV5

#pragma mark - File Content Encryption and Decryption

- (void)encryptFileAtPath:(NSString *)inPath toPath:(NSString *)outPath callback:(SETOCryptorCompletionCallback)callback progress:(SETOCryptorProgressCallback)progressCallback {
	NSParameterAssert(inPath);
	NSParameterAssert(outPath);
	NSParameterAssert(callback);

	// read cleartext file size:
	NSError *filesAttributesError;
	NSDictionary *fileAttributes = [[NSFileManager defaultManager] attributesOfItemAtPath:inPath error:&filesAttributesError];
	if (filesAttributesError) {
		callback(filesAttributesError);
		return;
	}
	uint64_t fileSize = [fileAttributes fileSize];

	// init progress:
	uint64_t bytesProcessed = 0;
	if (progressCallback) {
		progressCallback(0.0);
	}

	// allocate file header buffer:
	unsigned char header[kSETOCryptorV5HeaderLength];

	// create random iv:
	if (SecRandomCopyBytes(kSecRandomDefault, 16, header) == -1) {
		callback([NSError errorWithDomain:kSETOCryptorErrorDomain code:SETOCryptorEncryptionFailedError userInfo:nil]);
		return;
	}
	unsigned char *iv = &header[0];
	unsigned char *ciphertextHeaderPayload = &header[16];

	// create random file key:
	unsigned char fileKey[32];
	if (SecRandomCopyBytes(kSecRandomDefault, 32, fileKey) == -1) {
		callback([NSError errorWithDomain:kSETOCryptorErrorDomain code:SETOCryptorEncryptionFailedError userInfo:nil]);
		return;
	}

	// encrypt header data:
	unsigned char cleartextHeaderPayload[kSETOCryptorV5HeaderPayloadLength];
	fill_bytes(cleartextHeaderPayload, 0xFF, 0, 8);
	memcpy(&cleartextHeaderPayload[8], fileKey, sizeof(fileKey));
	{
		const EVP_CIPHER *ctrCipher = EVP_aes_256_ctr();
		EVP_CIPHER_CTX ctx;
		EVP_CIPHER_CTX_init(&ctx);
		EVP_CIPHER_CTX_set_padding(&ctx, 0);
		EVP_EncryptInit_ex(&ctx, ctrCipher, NULL, self.masterKey.aesMasterKey.bytes, iv);
		int bytesEncrypted = 0;
		int encryptStatus = EVP_EncryptUpdate(&ctx, ciphertextHeaderPayload, &bytesEncrypted, cleartextHeaderPayload, kSETOCryptorV5HeaderPayloadLength);
		if (encryptStatus == 0 || bytesEncrypted != kSETOCryptorV5HeaderPayloadLength) {
			EVP_CIPHER_CTX_cleanup(&ctx);
			callback([NSError errorWithDomain:kSETOCryptorErrorDomain code:SETOCryptorEncryptionFailedError userInfo:nil]);
			return;
		}
		EVP_CIPHER_CTX_cleanup(&ctx);
	}

	// calculate mac over file header:
	CCHmacContext headerHmacContext;
	CCHmacInit(&headerHmacContext, kCCHmacAlgSHA256, self.masterKey.macMasterKey.bytes, self.masterKey.macMasterKey.length);
	CCHmacUpdate(&headerHmacContext, header, 56);
	CCHmacFinal(&headerHmacContext, &header[56]);

	// open cleartext input stream:
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
	while (input.hasBytesAvailable) {
		// read chunk:
		int cleartextChunkLength = kSETOCryptorV5ChunkPayloadLength;
		unsigned char cleartextChunk[cleartextChunkLength];
		int inputLength = (int)[input read:cleartextChunk maxLength:cleartextChunkLength];
		if (inputLength == 0) {
			continue;
		} else if (inputLength < 0) {
			[input close];
			[output close];
			EVP_CIPHER_CTX_cleanup(&ctx);
			callback([NSError errorWithDomain:kSETOCryptorErrorDomain code:SETOCryptorEncryptionFailedError userInfo:nil]);
			return;
		}

		// calculate payload length:
		int payloadLength = (int)MIN(fileSize - bytesProcessed, kSETOCryptorV5ChunkPayloadLength);

		// init encryption:
		int ciphertextChunkLength = kSETOCryptorV5NonceLength + payloadLength + CC_SHA256_DIGEST_LENGTH;
		unsigned char ciphertextChunk[ciphertextChunkLength + kSETOCryptorV5BlockSize];
		unsigned char *nonce = &ciphertextChunk[0];
		if (SecRandomCopyBytes(kSecRandomDefault, 16, nonce) == -1) {
			callback([NSError errorWithDomain:kSETOCryptorErrorDomain code:SETOCryptorEncryptionFailedError userInfo:nil]);
			return;
		}
		EVP_EncryptInit_ex(&ctx, ctrCipher, NULL, fileKey, nonce);

		// encrypt chunk:
		int bytesEncrypted;
		unsigned char *payload = &ciphertextChunk[16];
		int encryptStatus = EVP_EncryptUpdate(&ctx, payload, &bytesEncrypted, cleartextChunk, inputLength);
		if (encryptStatus == 0 || bytesEncrypted != payloadLength) {
			[input close];
			[output close];
			EVP_CIPHER_CTX_cleanup(&ctx);
			callback([NSError errorWithDomain:kSETOCryptorErrorDomain code:SETOCryptorEncryptionFailedError userInfo:nil]);
			return;
		}

		// authenticate ciphertext chunk:
		unsigned char *chunkMac = &ciphertextChunk[kSETOCryptorV5NonceLength + bytesEncrypted];
		unsigned char chunkNumberBytes[sizeof(uint64_t)] = {0};
		long_to_big_endian_bytes(chunkNumber, chunkNumberBytes);
		CCHmacContext chunkHmacContext;
		CCHmacInit(&chunkHmacContext, kCCHmacAlgSHA256, self.masterKey.macMasterKey.bytes, self.masterKey.macMasterKey.length);
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
			callback([NSError errorWithDomain:kSETOCryptorErrorDomain code:SETOCryptorEncryptionFailedError userInfo:nil]);
			return;
		}

		// progress:
		bytesProcessed += payloadLength;
		chunkNumber++;
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

- (void)decryptFileAtPath:(NSString *)inPath toPath:(NSString *)outPath callback:(SETOCryptorCompletionCallback)callback progress:(SETOCryptorProgressCallback)progressCallback {
	NSParameterAssert(inPath);
	NSParameterAssert(outPath);
	NSParameterAssert(callback);

	// read ciphertext file size:
	NSError *filesAttributesError;
	NSDictionary *fileAttributes = [[NSFileManager defaultManager] attributesOfItemAtPath:inPath error:&filesAttributesError];
	if (filesAttributesError) {
		callback(filesAttributesError);
		return;
	}
	uint64_t fileSize = [fileAttributes fileSize];

	// open ciphertext input stream:
	NSInputStream *input = [NSInputStream inputStreamWithFileAtPath:inPath];
	[input scheduleInRunLoop:[NSRunLoop currentRunLoop] forMode:NSDefaultRunLoopMode];
	[input open];

	// read file header:
	unsigned char header[kSETOCryptorV5HeaderLength];
	int inputLength = (int)[input read:header maxLength:sizeof(header)];
	if (inputLength != sizeof(header)) {
		[input close];
		callback([NSError errorWithDomain:kSETOCryptorErrorDomain code:SETOCryptorCorruptedFileHeaderError userInfo:nil]);
		return;
	}

	// iv is at the beginning of file header:
	unsigned char *iv = &header[0];
	unsigned char *ciphertextHeaderPayload = &header[16];

	// decrypt header data:
	unsigned char cleartextHeaderPayload[kSETOCryptorV5HeaderPayloadLength + kSETOCryptorV5BlockSize];
	{
		const EVP_CIPHER *ctrCipher = EVP_aes_256_ctr();
		EVP_CIPHER_CTX ctx;
		EVP_CIPHER_CTX_init(&ctx);
		EVP_CIPHER_CTX_set_padding(&ctx, 0);
		EVP_DecryptInit_ex(&ctx, ctrCipher, NULL, self.masterKey.aesMasterKey.bytes, iv);
		int bytesDecrypted = 0;
		int decryptStatus = EVP_DecryptUpdate(&ctx, cleartextHeaderPayload, &bytesDecrypted, ciphertextHeaderPayload, kSETOCryptorV5HeaderPayloadLength);
		if (decryptStatus == 0 || bytesDecrypted != kSETOCryptorV5HeaderPayloadLength) {
			[input close];
			EVP_CIPHER_CTX_cleanup(&ctx);
			callback([NSError errorWithDomain:kSETOCryptorErrorDomain code:SETOCryptorCorruptedFileHeaderError userInfo:nil]);
			return;
		}
		EVP_CIPHER_CTX_cleanup(&ctx);
	}

	// extract file key:
	unsigned char *fileKey = &cleartextHeaderPayload[8];

	// initialize bytes processed:
	uint64_t bytesProcessed = 0;
	if (progressCallback) {
		progressCallback(0.0);
	}

	// open cleartext output stream:
	NSOutputStream *output = [NSOutputStream outputStreamToFileAtPath:outPath append:NO];
	[output scheduleInRunLoop:[NSRunLoop currentRunLoop] forMode:NSDefaultRunLoopMode];
	[output open];

	// decrypt content (ignoring chunk macs, assuming it's authentic):
	const EVP_CIPHER *ctrCipher = EVP_aes_256_ctr();
	EVP_CIPHER_CTX ctx;
	EVP_CIPHER_CTX_init(&ctx);
	EVP_CIPHER_CTX_set_padding(&ctx, 0);
	while (input.hasBytesAvailable) {
		// read chunk:
		int ciphertextChunkLength = kSETOCryptorV5NonceLength + kSETOCryptorV5ChunkPayloadLength + CC_SHA256_DIGEST_LENGTH;
		unsigned char ciphertextChunk[ciphertextChunkLength];
		int inputLength = (int)[input read:ciphertextChunk maxLength:ciphertextChunkLength];
		if (inputLength == 0) {
			continue;
		} else if (inputLength < kSETOCryptorV5NonceLength + CC_SHA256_DIGEST_LENGTH) {
			[input close];
			[output close];
			EVP_CIPHER_CTX_cleanup(&ctx);
			callback([NSError errorWithDomain:kSETOCryptorErrorDomain code:SETOCryptorDecryptionFailedError userInfo:nil]);
			return;
		}

		// init decryption:
		unsigned char *nonce = &ciphertextChunk[0];
		unsigned char *payload = &ciphertextChunk[kSETOCryptorV5NonceLength];
		EVP_DecryptInit_ex(&ctx, ctrCipher, NULL, fileKey, nonce);

		// calculate payload length:
		int payloadLength = inputLength - kSETOCryptorV5NonceLength - CC_SHA256_DIGEST_LENGTH;

		// decrypt chunk:
		int cleartextChunkLength = payloadLength + kSETOCryptorV5BlockSize;
		unsigned char cleartextChunk[cleartextChunkLength];
		int outputLength = 0;
		int decryptStatus = EVP_DecryptUpdate(&ctx, cleartextChunk, &outputLength, payload, payloadLength);
		if (decryptStatus == 0) {
			[input close];
			[output close];
			EVP_CIPHER_CTX_cleanup(&ctx);
			callback([NSError errorWithDomain:kSETOCryptorErrorDomain code:SETOCryptorDecryptionFailedError userInfo:nil]);
			return;
		}

		// write cleartext chunk:
		int bytesWritten = (int)[output write:cleartextChunk maxLength:outputLength];
		if (bytesWritten != outputLength) {
			[input close];
			[output close];
			EVP_CIPHER_CTX_cleanup(&ctx);
			callback([NSError errorWithDomain:kSETOCryptorErrorDomain code:SETOCryptorDecryptionFailedError userInfo:nil]);
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

#pragma mark - File Size Calculation

- (NSUInteger)ciphertextSizeFromCleartextSize:(NSUInteger)cleartextSize {
	NSUInteger cleartextChunkSize = kSETOCryptorV5ChunkPayloadLength;
	NSUInteger ciphertextChunkSize = kSETOCryptorV5NonceLength + cleartextChunkSize + CC_SHA256_DIGEST_LENGTH;
	NSUInteger overheadPerChunk = ciphertextChunkSize - cleartextChunkSize;
	NSUInteger numFullChunks = cleartextSize / cleartextChunkSize; // floor by int-truncation
	NSUInteger additionalCleartextBytes = cleartextSize % cleartextChunkSize;
	NSUInteger additionalCiphertextBytes = (additionalCleartextBytes == 0) ? 0 : additionalCleartextBytes + overheadPerChunk;
	return ciphertextChunkSize * numFullChunks + additionalCiphertextBytes;
}

- (NSUInteger)cleartextSizeFromCiphertextSize:(NSUInteger)ciphertextSize {
	NSUInteger cleartextChunkSize = kSETOCryptorV5ChunkPayloadLength;
	NSUInteger ciphertextChunkSize = kSETOCryptorV5NonceLength + cleartextChunkSize + CC_SHA256_DIGEST_LENGTH;
	NSUInteger overheadPerChunk = ciphertextChunkSize - cleartextChunkSize;
	NSUInteger numFullChunks = ciphertextSize / ciphertextChunkSize; // floor by int-truncation
	NSUInteger additionalCiphertextBytes = ciphertextSize % ciphertextChunkSize;
	if (additionalCiphertextBytes > 0 && additionalCiphertextBytes <= overheadPerChunk) {
		NSLog(@"-[SETOCryptor cleartextSizeFromCiphertextSize:] not defined for input value %tu", ciphertextSize);
		return NSUIntegerMax;
	}
	NSUInteger additionalCleartextBytes = (additionalCiphertextBytes == 0) ? 0 : additionalCiphertextBytes - overheadPerChunk;
	return cleartextChunkSize * numFullChunks + additionalCleartextBytes;
}

@end
