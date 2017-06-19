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
#import "SETOMasterKey.h"

@interface SETOCryptorProviderTests : XCTestCase
@end

@implementation SETOCryptorProviderTests

- (void)testNewCryptorWithNewMasterKey {
	// create master key:
	SETOCryptor *cryptor1 = [SETOCryptorProvider newCryptor];
	XCTAssertNotNil(cryptor1);
	SETOMasterKey *masterKey = [cryptor1 masterKeyWithPassword:@"asd"];
	XCTAssertNotNil(masterKey);

	// successful unlock of newly created key:
	NSError *error;
	SETOCryptor *cryptor2 = [SETOCryptorProvider cryptorFromMasterKey:masterKey withPassword:@"asd" error:&error];
	XCTAssertNotNil(cryptor2);
	XCTAssertNil(error);

	// cryptor with invalid password:
	SETOCryptor *cryptor3 = [SETOCryptorProvider cryptorFromMasterKey:masterKey withPassword:@"qwe" error:&error];
	XCTAssertNil(cryptor3);
	XCTAssertEqual(error.domain, kSETOCryptorProviderErrorDomain);
	XCTAssertEqual(error.code, SETOCryptorProviderInvalidPasswordError);
}

- (void)testDifferentNormalizationFormsOfPassword {
	// create master key:
	SETOCryptor *cryptor = [SETOCryptorProvider newCryptor];
	XCTAssertNotNil(cryptor);
	SETOMasterKey *masterKey = [cryptor masterKeyWithPassword:@"țț"]; // NFC + NFD
	XCTAssertNotNil(masterKey);

	// test different normalization forms of password:
	NSError *error;
	XCTAssertNotNil([SETOCryptorProvider cryptorFromMasterKey:masterKey withPassword:@"țț" error:&error]); // NFC + NFD
	XCTAssertNil(error);
	XCTAssertNotNil([SETOCryptorProvider cryptorFromMasterKey:masterKey withPassword:@"țț" error:&error]); // NFC + NFC
	XCTAssertNil(error);
	XCTAssertNotNil([SETOCryptorProvider cryptorFromMasterKey:masterKey withPassword:@"țț" error:&error]); // NFD + NFD
	XCTAssertNil(error);
	XCTAssertNotNil([SETOCryptorProvider cryptorFromMasterKey:masterKey withPassword:@"țț" error:&error]); // NFD + NFC
	XCTAssertNil(error);
}

@end
