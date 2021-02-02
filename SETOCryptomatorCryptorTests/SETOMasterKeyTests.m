//
//  SETOMasterKeyTests.m
//  SETOCryptomatorCryptorTests
//
//  Created by Tobias Hagemann on 01.02.21.
//  Copyright © 2021 Skymatic. All rights reserved.
//

#import <XCTest/XCTest.h>
#import "SETOMasterKey.h"

@interface SETOMasterKeyTests : XCTestCase
@end

@implementation SETOMasterKeyTests

- (void)testInitialization {
	unsigned char aesMasterKeyBuffer[] = {[0 ... 31] = 0x77};
	NSData *aesMasterKey = [NSData dataWithBytes:aesMasterKeyBuffer length:sizeof(aesMasterKeyBuffer)];
	unsigned char macMasterKeyBuffer[] = {[0 ... 31] = 0x55};
	NSData *macMasterKey = [NSData dataWithBytes:macMasterKeyBuffer length:sizeof(macMasterKeyBuffer)];
	SETOMasterKey *masterKey = [[SETOMasterKey alloc] initWithAESMasterKey:aesMasterKey macMasterkey:macMasterKey];
	XCTAssertEqual(aesMasterKey, masterKey.aesMasterKey);
	XCTAssertEqual(macMasterKey, masterKey.macMasterKey);
}

@end
