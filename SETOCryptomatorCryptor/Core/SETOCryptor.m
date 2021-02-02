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
@property (nonatomic, strong) SETOMasterKey *masterKey;
@end

@implementation SETOCryptor

#pragma mark - Initialization

- (instancetype)initWithMasterKey:(SETOMasterKey *)masterKey {
	if (self = [super init]) {
		self.masterKey = masterKey;
	}
	return self;
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

#pragma mark - File Size Calculation

- (NSUInteger)ciphertextSizeFromCleartextSize:(NSUInteger)cleartextSize {
	NSAssert(NO, @"Overwrite this method.");
	return NSUIntegerMax;
}

- (NSUInteger)cleartextSizeFromCiphertextSize:(NSUInteger)ciphertextSize {
	NSAssert(NO, @"Overwrite this method.");
	return NSUIntegerMax;
}

@end
