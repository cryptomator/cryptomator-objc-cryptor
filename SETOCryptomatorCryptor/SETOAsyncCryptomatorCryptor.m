//
//  SETOAsyncCryptomatorCryptor.m
//  SETOCryptomatorCryptor
//
//  Created by Tobias Hagemann on 18/04/15.
//  Copyright © 2015-2016 setoLabs. All rights reserved.
//

#import "SETOAsyncCryptomatorCryptor.h"

@interface SETOAsyncCryptomatorCryptor ()
@property (nonatomic, assign) dispatch_queue_t queue;
@end

@implementation SETOAsyncCryptomatorCryptor

- (instancetype)initWithMasterKey:(SETOMasterKey *)masterKey {
	dispatch_queue_t defaultPriorityQueue = dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0);
	return [self initWithMasterKey:masterKey queue:defaultPriorityQueue];
}

- (instancetype)initWithMasterKey:(SETOMasterKey *)masterKey queue:(dispatch_queue_t)queue {
	NSParameterAssert(masterKey);
	NSParameterAssert(queue);
	if (self = [super initWithMasterKey:masterKey]) {
		self.queue = queue;
	}
	return self;
}

- (void)authenticateFileAtPath:(NSString *)path callback:(SETOCryptomatorCryptorCompletionCallback)callback progress:(SETOCryptomatorCryptorProgressCallback)progressCallback {
	NSParameterAssert(path);
	NSParameterAssert(callback);
	dispatch_async(self.queue, ^{
		[super authenticateFileAtPath:path callback:^(NSError *error) {
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

- (void)encryptFileAtPath:(NSString *)inPath toPath:(NSString *)outPath callback:(SETOCryptomatorCryptorCompletionCallback)callback progress:(SETOCryptomatorCryptorProgressCallback)progressCallback {
	NSParameterAssert(inPath);
	NSParameterAssert(outPath);
	NSParameterAssert(callback);
	dispatch_async(self.queue, ^{
		[super encryptFileAtPath:inPath toPath:outPath callback:^(NSError *error) {
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

- (void)decryptFileAtPath:(NSString *)inPath toPath:(NSString *)outPath callback:(SETOCryptomatorCryptorCompletionCallback)callback progress:(SETOCryptomatorCryptorProgressCallback)progressCallback {
	NSParameterAssert(inPath);
	NSParameterAssert(outPath);
	NSParameterAssert(callback);
	dispatch_async(self.queue, ^{
		[super decryptFileAtPath:inPath toPath:outPath callback:^(NSError *error) {
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

@end
