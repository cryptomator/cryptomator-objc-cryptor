//
//  SETOCryptor.m
//  SETOCryptomatorCryptor
//
//  Created by Sebastian Stenzel on 14.02.15.
//  Copyright © 2015-2017 Skymatic. All rights reserved.
//

#import "SETOCryptor.h"
#import "SETOMasterKey.h"

NSString *const kSETOCryptorErrorDomain = @"SETOCryptorErrorDomain";

@interface SETOCryptor ()
@property (nonatomic, copy) NSData *primaryMasterKey;
@property (nonatomic, copy) NSData *macMasterKey;
@property (nonatomic, assign) SETOCryptorVersion version;
@end

@implementation SETOCryptor

#pragma mark - Initialization

- (instancetype)initWithPrimaryMasterKey:(NSData *)primaryMasterKey macMasterKey:(NSData *)macMasterKey version:(SETOCryptorVersion)version {
	if (self = [super init]) {
		self.primaryMasterKey = primaryMasterKey;
		self.macMasterKey = macMasterKey;
		self.version = version;
	}
	return self;
}

- (SETOMasterKey *)masterKeyWithPassword:(NSString *)password {
	return [self masterKeyWithPassword:password pepper:nil];
}

- (SETOMasterKey *)masterKeyWithPassword:(NSString *)password pepper:(NSData *)pepper {
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

#pragma mark - Chunk Sizes

- (NSUInteger)cleartextChunkSize {
	NSAssert(NO, @"Overwrite this method.");
	return NSUIntegerMax;
}

- (NSUInteger)ciphertextChunkSize {
	NSAssert(NO, @"Overwrite this method.");
	return NSUIntegerMax;
}

@end
