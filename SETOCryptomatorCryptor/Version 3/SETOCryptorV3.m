//
//  SETOCryptorV3.m
//  SETOCryptomatorCryptor
//
//  Created by Tobias Hagemann on 22.06.16.
//  Copyright © 2015-2017 Skymatic. All rights reserved.
//

#import "SETOCryptorV3.h"
#import "SETOMasterKey.h"

#import "SETOAesSivCipherUtil.h"
#import "SETOCryptoSupport.h"

#import <CommonCrypto/CommonDigest.h>
#import <CommonCrypto/CommonHMAC.h>
#import <Base32/MF_Base32Additions.h>
#import <openssl/evp.h>

size_t const kSETOCryptorV3BlockSize = 16;
int const kSETOCryptorV3NonceLength = 16;
int const kSETOCryptorV3HeaderLength = 88;
int const kSETOCryptorV3HeaderPayloadLength = 40;
int const kSETOCryptorV3ChunkPayloadLength = 32 * 1024;
NSString *const kSETOCryptorV3CiphertextFilenamePattern = @"^([A-Z2-7]{8})*[A-Z2-7=]{8}$";

@interface SETOCryptorV3 ()
@property (nonatomic, strong) SETOMasterKey *masterKey;
@end

@implementation SETOCryptorV3

#pragma mark - Path Encryption and Decryption

- (NSString *)encryptDirectoryId:(NSString *)directoryId {
	NSParameterAssert(directoryId);
	NSData *cleartext = [directoryId dataUsingEncoding:NSUTF8StringEncoding];
	unsigned char *ciphertext = malloc(cleartext.length + 16);
	if (siv_enc(self.masterKey.aesMasterKey.bytes, self.masterKey.macMasterKey.bytes, self.masterKey.aesMasterKey.length, cleartext.bytes, cleartext.length, 0, NULL, NULL, ciphertext)) {
		free(ciphertext);
		return nil;
	}
	unsigned char hashed[CC_SHA1_DIGEST_LENGTH];
	CC_SHA1(ciphertext, (CC_LONG)cleartext.length + 16, hashed);
	free(ciphertext);
	NSData *ciphertextData = [NSData dataWithBytes:hashed length:sizeof(hashed)];
	return [ciphertextData base32String];
}

- (NSString *)encryptFilename:(NSString *)filename insideDirectoryWithId:(NSString *)directoryId {
	NSParameterAssert(filename);
	NSData *cleartext = [filename dataUsingEncoding:NSUTF8StringEncoding];
	unsigned char *ciphertext = malloc(cleartext.length + 16);
	NSData *directoryIdData = [directoryId dataUsingEncoding:NSUTF8StringEncoding];
	const unsigned char *additionalData[1] = {directoryIdData.bytes};
	const size_t additionalDataSizes[1] = {directoryIdData.length};
	if (siv_enc(self.masterKey.aesMasterKey.bytes, self.masterKey.macMasterKey.bytes, self.masterKey.aesMasterKey.length, cleartext.bytes, cleartext.length, 1, additionalData, additionalDataSizes, ciphertext)) {
		free(ciphertext);
		return nil;
	}
	NSData *ciphertextData = [NSData dataWithBytesNoCopy:ciphertext length:cleartext.length + 16];
	return [self encodeFilename:ciphertextData];
}

- (NSString *)decryptFilename:(NSString *)filename insideDirectoryWithId:(NSString *)directoryId {
	NSParameterAssert(filename);
	if (![self isValidEncryptedFilename:filename]) {
		return nil;
	}
	NSData *ciphertext = [self decodeFilename:filename];
	if (!ciphertext) {
		return nil;
	}
	unsigned char *cleartext = malloc(ciphertext.length - 16);
	NSData *directoryIdData = [directoryId dataUsingEncoding:NSUTF8StringEncoding];
	const unsigned char *additionalData[1] = {directoryIdData.bytes};
	const size_t additionalDataSizes[1] = {directoryIdData.length};
	if (siv_dec(self.masterKey.aesMasterKey.bytes, self.masterKey.macMasterKey.bytes, self.masterKey.aesMasterKey.length, ciphertext.bytes, ciphertext.length, 1, additionalData, additionalDataSizes, cleartext)) {
		free(cleartext);
		return nil;
	}
	NSData *cleartextData = [NSData dataWithBytesNoCopy:cleartext length:ciphertext.length - 16];
	return [[NSString alloc] initWithData:cleartextData encoding:NSUTF8StringEncoding];
}

#pragma mark - Path Encoding and Decoding

- (NSString *)encodeFilename:(NSData *)filename {
	return [filename base32String];
}

- (NSData *)decodeFilename:(NSString *)filename {
	return [NSData dataWithBase32String:filename];
}

- (BOOL)isValidEncryptedFilename:(NSString *)filename {
	NSRegularExpression *regex = [NSRegularExpression regularExpressionWithPattern:kSETOCryptorV3CiphertextFilenamePattern options:NSRegularExpressionCaseInsensitive error:NULL];
	NSUInteger numberOfMatches = [regex numberOfMatchesInString:filename options:0 range:NSMakeRange(0, filename.length)];
	return numberOfMatches > 0;
}

#pragma mark - File Content Encryption and Decryption

- (void)authenticateFileAtPath:(NSString *)path callback:(SETOCryptorCompletionCallback)callback progress:(SETOCryptorProgressCallback)progressCallback {
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
	unsigned char header[kSETOCryptorV3HeaderLength];
	int inputLength = (int)[input read:header maxLength:sizeof(header)];
	if (inputLength != sizeof(header)) {
		[input close];
		callback([NSError errorWithDomain:kSETOCryptorErrorDomain code:SETOCryptorCorruptedFileHeaderError userInfo:nil]);
		return;
	}
	bytesProcessed += inputLength;

	// iv is at the beginning of file header:
	unsigned char *iv = &header[0];

	// calculate mac over file header:
	unsigned char calculatedHeaderMac[CC_SHA256_DIGEST_LENGTH];
	CCHmacContext headerHmacContext;
	CCHmacInit(&headerHmacContext, kCCHmacAlgSHA256, self.masterKey.macMasterKey.bytes, self.masterKey.macMasterKey.length);
	CCHmacUpdate(&headerHmacContext, header, 56); // 56 bytes: 16 bytes iv + 8 bytes file size + 32 bytes file key (without mac)
	CCHmacFinal(&headerHmacContext, calculatedHeaderMac);

	// calculate macs over file chunks:
	BOOL chunkMacsEqual = YES;
	uint64_t chunkNumber = 0;
	int ciphertextChunkLength = kSETOCryptorV3NonceLength + kSETOCryptorV3ChunkPayloadLength + CC_SHA256_DIGEST_LENGTH; // nonce + payload + mac
	NSMutableData *ciphertextChunk = [NSMutableData dataWithLength:ciphertextChunkLength];
	while (input.hasBytesAvailable) {
		// read chunk:
		unsigned char *ciphertextChunkBuffer = ciphertextChunk.mutableBytes;
		int inputLength = (int)[input read:ciphertextChunkBuffer maxLength:ciphertextChunkLength];
		if (inputLength == 0) {
			continue;
		} else if (inputLength < kSETOCryptorV3NonceLength + CC_SHA256_DIGEST_LENGTH) {
			[input close];
			callback([NSError errorWithDomain:kSETOCryptorErrorDomain code:SETOCryptorAuthenticationFailedError userInfo:nil]);
			return;
		}

		// init authentication:
		unsigned char *expectedMac = &ciphertextChunkBuffer[inputLength - CC_SHA256_DIGEST_LENGTH];
		unsigned char calculatedMac[CC_SHA256_DIGEST_LENGTH];
		unsigned char chunkNumberBytes[sizeof(uint64_t)] = {0};
		unsigned char *nonce = &ciphertextChunkBuffer[0];
		unsigned char *payload = &ciphertextChunkBuffer[kSETOCryptorV3NonceLength];
		int payloadLength = inputLength - kSETOCryptorV3NonceLength - CC_SHA256_DIGEST_LENGTH;
		long_to_big_endian_bytes(chunkNumber, chunkNumberBytes);

		// calculate chunk mac:
		CCHmacContext chunkHmacContext;
		CCHmacInit(&chunkHmacContext, kCCHmacAlgSHA256, self.masterKey.macMasterKey.bytes, self.masterKey.macMasterKey.length);
		CCHmacUpdate(&chunkHmacContext, iv, 16);
		CCHmacUpdate(&chunkHmacContext, chunkNumberBytes, sizeof(chunkNumberBytes));
		CCHmacUpdate(&chunkHmacContext, nonce, kSETOCryptorV3NonceLength);
		CCHmacUpdate(&chunkHmacContext, payload, payloadLength);
		CCHmacFinal(&chunkHmacContext, calculatedMac);

		// constant time comparison of chunk mac:
		chunkMacsEqual &= compare_bytes(calculatedMac, expectedMac, CC_SHA256_DIGEST_LENGTH);

		// progress:
		bytesProcessed += inputLength;
		chunkNumber++;
		if (progressCallback) {
			progressCallback((CGFloat)bytesProcessed / totalFileSize);
		}
	}

	// constant time comparison of header mac:
	unsigned char *expectedHeaderMac = &header[56];
	BOOL headerMacsEqual = compare_bytes(calculatedHeaderMac, expectedHeaderMac, CC_SHA256_DIGEST_LENGTH);

	// done:
	[input close];
	if (progressCallback) {
		progressCallback(1.0);
	}
	callback(headerMacsEqual && chunkMacsEqual ? nil : [NSError errorWithDomain:kSETOCryptorErrorDomain code:SETOCryptorAuthenticationFailedError userInfo:nil]);
}

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
	unsigned char header[kSETOCryptorV3HeaderLength];

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
	unsigned char cleartextHeaderPayload[kSETOCryptorV3HeaderPayloadLength];
	long_to_big_endian_bytes(fileSize, cleartextHeaderPayload);
	memcpy(&cleartextHeaderPayload[8], fileKey, sizeof(fileKey));
	{
		const EVP_CIPHER *ctrCipher = EVP_aes_256_ctr();
		EVP_CIPHER_CTX ctx;
		EVP_CIPHER_CTX_init(&ctx);
		EVP_CIPHER_CTX_set_padding(&ctx, 0);
		EVP_EncryptInit_ex(&ctx, ctrCipher, NULL, self.masterKey.aesMasterKey.bytes, iv);
		int bytesEncrypted = 0;
		int encryptStatus = EVP_EncryptUpdate(&ctx, ciphertextHeaderPayload, &bytesEncrypted, cleartextHeaderPayload, kSETOCryptorV3HeaderPayloadLength);
		if (encryptStatus == 0 || bytesEncrypted != kSETOCryptorV3HeaderPayloadLength) {
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
	while (input.hasBytesAvailable && bytesProcessed < bytesTotal) {
		// read chunk:
		int cleartextChunkLength = kSETOCryptorV3ChunkPayloadLength;
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

		// add padding if necessary:
		uint64_t bytesRemaining = bytesTotal - bytesProcessed;
		int payloadLength = (int)MIN(bytesRemaining, kSETOCryptorV3ChunkPayloadLength);
		int paddingLength = payloadLength - inputLength;
		arc4random_buf(&cleartextChunk[inputLength], paddingLength);
		inputLength += paddingLength;

		// init encryption:
		int ciphertextChunkLength = kSETOCryptorV3NonceLength + payloadLength + CC_SHA256_DIGEST_LENGTH;
		unsigned char ciphertextChunk[ciphertextChunkLength + kSETOCryptorV3BlockSize];
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
		unsigned char *chunkMac = &ciphertextChunk[kSETOCryptorV3NonceLength + bytesEncrypted];
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

- (void)decryptFileAtPath:(NSString *)inPath toPath:(NSString *)outPath callback:(SETOCryptorCompletionCallback)callback progress:(SETOCryptorProgressCallback)progressCallback {
	NSParameterAssert(inPath);
	NSParameterAssert(outPath);
	NSParameterAssert(callback);

	// open ciphertext input stream:
	NSInputStream *input = [NSInputStream inputStreamWithFileAtPath:inPath];
	[input scheduleInRunLoop:[NSRunLoop currentRunLoop] forMode:NSDefaultRunLoopMode];
	[input open];

	// read file header:
	unsigned char header[kSETOCryptorV3HeaderLength];
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
	unsigned char cleartextHeaderPayload[kSETOCryptorV3HeaderPayloadLength + kSETOCryptorV3BlockSize];
	{
		const EVP_CIPHER *ctrCipher = EVP_aes_256_ctr();
		EVP_CIPHER_CTX ctx;
		EVP_CIPHER_CTX_init(&ctx);
		EVP_CIPHER_CTX_set_padding(&ctx, 0);
		EVP_DecryptInit_ex(&ctx, ctrCipher, NULL, self.masterKey.aesMasterKey.bytes, iv);
		int bytesDecrypted = 0;
		int decryptStatus = EVP_DecryptUpdate(&ctx, cleartextHeaderPayload, &bytesDecrypted, ciphertextHeaderPayload, kSETOCryptorV3HeaderPayloadLength);
		if (decryptStatus == 0 || bytesDecrypted != kSETOCryptorV3HeaderPayloadLength) {
			[input close];
			EVP_CIPHER_CTX_cleanup(&ctx);
			callback([NSError errorWithDomain:kSETOCryptorErrorDomain code:SETOCryptorCorruptedFileHeaderError userInfo:nil]);
			return;
		}
		EVP_CIPHER_CTX_cleanup(&ctx);
	}

	// extract file size and file key:
	uint64_t fileSize = big_endian_bytes_to_long(&cleartextHeaderPayload[0]);
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
	while (input.hasBytesAvailable && bytesProcessed < fileSize) {
		// read chunk:
		int ciphertextChunkLength = kSETOCryptorV3NonceLength + kSETOCryptorV3ChunkPayloadLength + CC_SHA256_DIGEST_LENGTH;
		unsigned char ciphertextChunk[ciphertextChunkLength];
		int inputLength = (int)[input read:ciphertextChunk maxLength:ciphertextChunkLength];
		if (inputLength == 0) {
			continue;
		} else if (inputLength < kSETOCryptorV3NonceLength + CC_SHA256_DIGEST_LENGTH) {
			[input close];
			[output close];
			EVP_CIPHER_CTX_cleanup(&ctx);
			callback([NSError errorWithDomain:kSETOCryptorErrorDomain code:SETOCryptorDecryptionFailedError userInfo:nil]);
			return;
		}

		// init decryption:
		unsigned char *nonce = &ciphertextChunk[0];
		unsigned char *payload = &ciphertextChunk[kSETOCryptorV3NonceLength];
		EVP_DecryptInit_ex(&ctx, ctrCipher, NULL, fileKey, nonce);

		// calculate payload length:
		int payloadLength = inputLength - kSETOCryptorV3NonceLength - CC_SHA256_DIGEST_LENGTH;
		uint64_t remainingFileSize = fileSize - bytesProcessed;
		int remainingPayloadLength = payloadLength < remainingFileSize ? payloadLength : (int)remainingFileSize; // ignore padding if necessary

		// decrypt chunk:
		int cleartextChunkLength = payloadLength + kSETOCryptorV3BlockSize;
		unsigned char cleartextChunk[cleartextChunkLength];
		int outputLength = 0;
		int decryptStatus = EVP_DecryptUpdate(&ctx, cleartextChunk, &outputLength, payload, remainingPayloadLength);
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
	NSLog(@"-[SETOCryptor cleartextSizeFromCiphertextSize:] not defined for cryptor version 3 and 4");
	return NSUIntegerMax;
}

- (NSUInteger)cleartextSizeFromCiphertextSize:(NSUInteger)ciphertextSize {
	NSLog(@"-[SETOCryptor cleartextSizeFromCiphertextSize:] not defined for cryptor version 3 and 4");
	return NSUIntegerMax;
}

@end
