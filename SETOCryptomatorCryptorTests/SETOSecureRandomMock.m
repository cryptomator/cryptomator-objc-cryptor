//
//  SETOSecureRandomMock.m
//  SETOCryptomatorCryptorTests
//
//  Created by Tobias Hagemann on 02.02.21.
//  Copyright © 2021 Skymatic. All rights reserved.
//

#import "SETOSecureRandomMock.h"

@implementation SETOSecureRandomMock

- (NSData *)generateDataWithSize:(NSUInteger)size error:(NSError **)error {
	unsigned char emptyBuffer[size];
	memset(emptyBuffer, 0xf0, size);
	return [NSData dataWithBytes:emptyBuffer length:size];
}

@end
