//
//  SETOSecureRandom.m
//  SETOCryptomatorCryptor
//
//  Created by Tobias Hagemann on 01.02.21.
//  Copyright © 2021 Skymatic. All rights reserved.
//

#import "SETOSecureRandom.h"

#import <Security/Security.h>

NSString *const kSETOSecureRandomErrorDomain = @"SETOSecureRandomErrorDomain";

@implementation SETOSecureRandom

+ (instancetype)sharedInstance {
	static SETOSecureRandom *sharedInstance;
	static dispatch_once_t onceToken;
	dispatch_once(&onceToken, ^{
		sharedInstance = [[SETOSecureRandom alloc] init];
	});
	return sharedInstance;
}

- (NSData *)generateDataWithSize:(NSUInteger)size error:(NSError **)error {
	unsigned char buffer[size];
	if (SecRandomCopyBytes(kSecRandomDefault, size, buffer) == -1) {
		NSLog(@"Unable to create random bytes.");
		if (error) {
			*error = [NSError errorWithDomain:kSETOSecureRandomErrorDomain code:SETOSecureRandomGenerationFailedError userInfo:nil];
		}
		return nil;
	}
	return [NSData dataWithBytes:buffer length:size];
}

@end
