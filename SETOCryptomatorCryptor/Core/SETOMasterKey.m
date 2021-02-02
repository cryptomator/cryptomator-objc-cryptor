//
//  SETOMasterKey.m
//  SETOCryptomatorCryptor
//
//  Created by Tobias Hagemann on 21.02.15.
//  Copyright © 2015-2017 Skymatic. All rights reserved.
//

#import "SETOMasterKey.h"

#import "SETOSecureRandom.h"

#import <CommonCrypto/CommonCrypto.h>

@interface SETOMasterKey ()
@property (nonatomic, copy) NSData *aesMasterKey;
@property (nonatomic, copy) NSData *macMasterKey;
@end

@implementation SETOMasterKey

- (instancetype)initWithAESMasterKey:(NSData *)aesMasterKey macMasterkey:(NSData *)macMasterKey {
	NSParameterAssert(aesMasterKey.length == kCCKeySizeAES256);
	NSParameterAssert(macMasterKey.length == kCCKeySizeAES256);
	if (self = [super init]) {
		self.aesMasterKey = aesMasterKey;
		self.macMasterKey = macMasterKey;
	}
	return self;
}

- (instancetype)init {
	if ([NSThread isMainThread]) {
		NSLog(@"Warning: This method should be called from a background thread, as random number generation will benefit from UI interaction.");
	}
	if (self = [super init]) {
		// create random bytes for aes master key:
		self.aesMasterKey = [[SETOSecureRandom sharedInstance] generateDataWithSize:kCCKeySizeAES256 error:NULL];
		if (!self.aesMasterKey) {
			NSLog(@"Unable to create random bytes for aesMasterKeyBuffer.");
			return nil;
		}

		// create random bytes for mac master key:
		self.macMasterKey = [[SETOSecureRandom sharedInstance] generateDataWithSize:kCCKeySizeAES256 error:NULL];
		if (!self.macMasterKey) {
			NSLog(@"Unable to create random bytes for macMasterKeyBuffer.");
			return nil;
		}
	}
	return self;
}

@end
