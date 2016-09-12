//
//  SETOCryptorProviderTests.m
//  SETOCryptomatorCryptor
//
//  Created by Tobias Hagemann on 12/09/16.
//  Copyright © 2016 setoLabs. All rights reserved.
//

#import <XCTest/XCTest.h>
#import "SETOCryptorProvider.h"
#import "SETOCryptor.h"

@interface SETOCryptorProviderTests : XCTestCase
@end

@implementation SETOCryptorProviderTests

- (void)testNewCryptorWithNewMasterKey {
	// create key:
	SETOCryptor *cryptor1 = [SETOCryptorProvider newCryptor];
	XCTAssertNotNil(cryptor1);
	SETOMasterKey *key = [cryptor1 masterKeyWithPassword:@"asd"];
	XCTAssertNotNil(key);

	// successful unlock of newly created key:
	NSError *error;
	SETOCryptor *cryptor2 = [SETOCryptorProvider cryptorFromMasterKey:key withPassword:@"asd" error:&error];
	XCTAssertNotNil(cryptor2);
	XCTAssertNil(error);

	// cryptor with invalid password:
	SETOCryptor *cryptor3 = [SETOCryptorProvider cryptorFromMasterKey:key withPassword:@"qwe" error:&error];
	XCTAssertNil(cryptor3);
	XCTAssertEqual(error.domain, kSETOCryptorProviderErrorDomain);
	XCTAssertEqual(error.code, SETOCryptorProviderInvalidPasswordError);
}

@end
