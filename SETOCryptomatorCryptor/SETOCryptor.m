//
//  SETOCryptor.m
//  SETOCryptomatorCryptor
//
//  Created by Sebastian Stenzel on 14/02/15.
//  Copyright © 2015-2016 setoLabs. All rights reserved.
//

#import "SETOCryptor.h"
#import "SETOMasterKey.h"

NSString *const kSETOCryptorErrorDomain = @"SETOCryptorErrorDomain";

@interface SETOCryptor ()
@property (nonatomic, copy) NSData *primaryMasterKey;
@property (nonatomic, copy) NSData *macMasterKey;
@end

@implementation SETOCryptor

#pragma mark - Initialization

- (instancetype)initWithPrimaryMasterKey:(NSData *)primaryMasterKey macMasterKey:(NSData *)macMasterKey {
	if (self = [super init]) {
		self.primaryMasterKey = primaryMasterKey;
		self.macMasterKey = macMasterKey;
	}
	return self;
}

- (SETOMasterKey *)masterKeyWithPassword:(NSString *)password {
	NSAssert(NO, @"Overwrite this method.");
	return nil;
}

#pragma mark - Path Encryption and Decryption

- (NSString *)encryptDirectoryId:(NSString *)directoryId {
	NSAssert(NO, @"Overwrite this method.");
	return nil;
}

- (NSString *)encryptFilename:(NSString *)filename insideDirectoryWithId:(NSString *)directoryId {
	NSAssert(NO, @"Overwrite this method.");
	return nil;
}

- (NSString *)decryptFilename:(NSString *)filename insideDirectoryWithId:(NSString *)directoryId {
	NSAssert(NO, @"Overwrite this method.");
	return nil;
}

#pragma mark - File Content Encryption and Decryption

- (void)authenticateFileAtPath:(NSString *)path callback:(SETOCryptorCompletionCallback)callback progress:(SETOCryptorProgressCallback)progressCallback {
	NSAssert(NO, @"Overwrite this method.");
}

- (void)encryptFileAtPath:(NSString *)inPath toPath:(NSString *)outPath callback:(SETOCryptorCompletionCallback)callback progress:(SETOCryptorProgressCallback)progressCallback {
	NSAssert(NO, @"Overwrite this method.");
}

- (void)decryptFileAtPath:(NSString *)inPath toPath:(NSString *)outPath callback:(SETOCryptorCompletionCallback)callback progress:(SETOCryptorProgressCallback)progressCallback {
	NSAssert(NO, @"Overwrite this method.");
}

@end
