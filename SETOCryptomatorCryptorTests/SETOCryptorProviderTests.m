//
//  SETOCryptorProviderTests.m
//  SETOCryptomatorCryptor
//
//  Created by Tobias Hagemann on 12.09.16.
//  Copyright © 2015-2017 Skymatic. All rights reserved.
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

- (void)testNewCryptorWithNewMasterKeyAndPepper {
	// create pepper:
	unsigned char pepperBuffer[1] = {0x01};
	NSData *pepper = [NSData dataWithBytes:pepperBuffer length:1];

	// create master key:
	SETOCryptor *cryptor1 = [SETOCryptorProvider newCryptor];
	XCTAssertNotNil(cryptor1);
	SETOMasterKey *masterKey = [cryptor1 masterKeyWithPassword:@"asd" pepper:pepper];
	XCTAssertNotNil(masterKey);

	// successful unlock of newly created key:
	NSError *error;
	SETOCryptor *cryptor2 = [SETOCryptorProvider cryptorFromMasterKey:masterKey withPassword:@"asd" pepper:pepper error:&error];
	XCTAssertNotNil(cryptor2);
	XCTAssertNil(error);

	// cryptor with invalid password:
	SETOCryptor *cryptor3 = [SETOCryptorProvider cryptorFromMasterKey:masterKey withPassword:@"qwe" pepper:pepper error:&error];
	XCTAssertNil(cryptor3);
	XCTAssertEqual(error.domain, kSETOCryptorProviderErrorDomain);
	XCTAssertEqual(error.code, SETOCryptorProviderInvalidPasswordError);

	// cryptor with invalid pepper:
	unsigned char invalidPepperBuffer[1] = {0x02};
	NSData *invalidPepper = [NSData dataWithBytes:invalidPepperBuffer length:1];
	SETOCryptor *cryptor4 = [SETOCryptorProvider cryptorFromMasterKey:masterKey withPassword:@"asd" pepper:invalidPepper error:&error];
	XCTAssertNil(cryptor4);
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
