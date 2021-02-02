//
//  SETOAsyncCryptor.m
//  SETOCryptomatorCryptor
//
//  Created by Tobias Hagemann on 18.04.15.
//  Copyright © 2015-2017 Skymatic. All rights reserved.
//

#import "SETOAsyncCryptor.h"

@interface SETOAsyncCryptor ()
@property (nonatomic, strong) SETOCryptor *cryptor;
@property (nonatomic, strong) dispatch_queue_t queue;
@end

@implementation SETOAsyncCryptor

#pragma mark - Initialization

- (instancetype)initWithCryptor:(SETOCryptor *)cryptor queue:(dispatch_queue_t)queue {
	NSParameterAssert(cryptor);
	NSParameterAssert(queue);
	if (self = [super initWithMasterKey:nil]) {
		self.cryptor = cryptor;
		self.queue = queue;
	}
	return self;
}

- (instancetype)initWithCryptor:(SETOCryptor *)cryptor {
	dispatch_queue_attr_t qosAttribute = dispatch_queue_attr_make_with_qos_class(DISPATCH_QUEUE_SERIAL, QOS_CLASS_UTILITY, 0);
	dispatch_queue_t queue = dispatch_queue_create("org.cryptomator.SETOAsyncCryptorQueue", qosAttribute);
	return [self initWithCryptor:cryptor queue:queue];
}

#pragma mark - Path Encryption and Decryption

- (NSString *)encryptDirectoryId:(NSString *)directoryId {
	return [self.cryptor encryptDirectoryId:directoryId];
}

- (NSString *)encryptFilename:(NSString *)filename insideDirectoryWithId:(NSString *)directoryId {
	return [self.cryptor encryptFilename:filename insideDirectoryWithId:directoryId];
}

- (NSString *)decryptFilename:(NSString *)filename insideDirectoryWithId:(NSString *)directoryId {
	return [self.cryptor decryptFilename:filename insideDirectoryWithId:directoryId];
}

#pragma mark - File Content Encryption and Decryption

- (void)authenticateFileAtPath:(NSString *)path callback:(SETOCryptorCompletionCallback)callback progress:(SETOCryptorProgressCallback)progressCallback {
	NSParameterAssert(callback);
	dispatch_async(self.queue, ^{
		[self.cryptor authenticateFileAtPath:path callback:^(NSError *error) {
			dispatch_async(dispatch_get_main_queue(), ^{
				callback(error);
			});
		} progress:^(CGFloat progress) {
			if (progressCallback) {
				dispatch_async(dispatch_get_main_queue(), ^{
					progressCallback(progress);
				});
			}
		}];
	});
}

- (void)encryptFileAtPath:(NSString *)inPath toPath:(NSString *)outPath callback:(SETOCryptorCompletionCallback)callback progress:(SETOCryptorProgressCallback)progressCallback {
	NSParameterAssert(callback);
	dispatch_async(self.queue, ^{
		[self.cryptor encryptFileAtPath:inPath toPath:outPath callback:^(NSError *error) {
			dispatch_async(dispatch_get_main_queue(), ^{
				callback(error);
			});
		} progress:^(CGFloat progress) {
			if (progressCallback) {
				dispatch_async(dispatch_get_main_queue(), ^{
					progressCallback(progress);
				});
			}
		}];
	});
}

- (void)decryptFileAtPath:(NSString *)inPath toPath:(NSString *)outPath callback:(SETOCryptorCompletionCallback)callback progress:(SETOCryptorProgressCallback)progressCallback {
	NSParameterAssert(callback);
	dispatch_async(self.queue, ^{
		[self.cryptor decryptFileAtPath:inPath toPath:outPath callback:^(NSError *error) {
			dispatch_async(dispatch_get_main_queue(), ^{
				callback(error);
			});
		} progress:^(CGFloat progress) {
			if (progressCallback) {
				dispatch_async(dispatch_get_main_queue(), ^{
					progressCallback(progress);
				});
			}
		}];
	});
}

#pragma mark - Chunk Sizes

- (NSUInteger)ciphertextSizeFromCleartextSize:(NSUInteger)cleartextSize {
	return [self.cryptor ciphertextSizeFromCleartextSize:cleartextSize];
}

- (NSUInteger)cleartextSizeFromCiphertextSize:(NSUInteger)ciphertextSize {
	return [self.cryptor cleartextSizeFromCiphertextSize:ciphertextSize];
}

@end
