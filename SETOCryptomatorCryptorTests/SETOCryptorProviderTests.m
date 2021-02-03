//
//  SETOCryptorProviderTests.m
//  SETOCryptomatorCryptorTests
//
//  Created by Tobias Hagemann on 03.02.21.
//  Copyright © 2021 Skymatic. All rights reserved.
//

#import <XCTest/XCTest.h>
#import "SETOCryptorProvider.h"
#import "SETOCryptorV3.h"
#import "SETOCryptorV5.h"
#import "SETOCryptorV7.h"
#import "SETOMasterKey.h"

@interface SETOCryptorProviderTests : XCTestCase
@end

@implementation SETOCryptorProviderTests

- (void)testCreatingCryptorForSupportedVersions {
	SETOMasterKey *masterKey = [[SETOMasterKey alloc] init];

	NSError *error1;
	SETOCryptor *cryptor1 = [SETOCryptorProvider cryptorWithMasterKey:masterKey forVaultVersion:3 error:&error1];
	XCTAssertNotNil(cryptor1);
	XCTAssertTrue([cryptor1 isKindOfClass:[SETOCryptorV3 class]]);
	XCTAssertNil(error1);

	NSError *error2;
	SETOCryptor *cryptor2 = [SETOCryptorProvider cryptorWithMasterKey:masterKey forVaultVersion:4 error:&error2];
	XCTAssertNotNil(cryptor2);
	XCTAssertTrue([cryptor2 isKindOfClass:[SETOCryptorV3 class]]);
	XCTAssertNil(error2);

	NSError *error3;
	SETOCryptor *cryptor3 = [SETOCryptorProvider cryptorWithMasterKey:masterKey forVaultVersion:5 error:&error3];
	XCTAssertNotNil(cryptor3);
	XCTAssertTrue([cryptor3 isKindOfClass:[SETOCryptorV5 class]]);
	XCTAssertNil(error3);

	NSError *error4;
	SETOCryptor *cryptor4 = [SETOCryptorProvider cryptorWithMasterKey:masterKey forVaultVersion:6 error:&error4];
	XCTAssertNotNil(cryptor4);
	XCTAssertTrue([cryptor4 isKindOfClass:[SETOCryptorV5 class]]);
	XCTAssertNil(error4);

	NSError *error5;
	SETOCryptor *cryptor5 = [SETOCryptorProvider cryptorWithMasterKey:masterKey forVaultVersion:7 error:&error5];
	XCTAssertNotNil(cryptor5);
	XCTAssertTrue([cryptor5 isKindOfClass:[SETOCryptorV7 class]]);
	XCTAssertNil(error5);

	NSError *error6;
	SETOCryptor *cryptor6 = [SETOCryptorProvider cryptorWithMasterKey:masterKey forVaultVersion:8 error:&error6];
	XCTAssertNotNil(cryptor6);
	XCTAssertTrue([cryptor6 isKindOfClass:[SETOCryptorV7 class]]);
	XCTAssertNil(error6);
}

- (void)testCreatingSupportForUnsupportedVersions {
	SETOMasterKey *masterKey = [[SETOMasterKey alloc] init];
	for (NSInteger vaultVersion = -1; vaultVersion < 10; vaultVersion++) {
		if (vaultVersion >= 3 && vaultVersion <= 8) {
			continue;
		}
		NSError *error;
		SETOCryptor *cryptor = [SETOCryptorProvider cryptorWithMasterKey:masterKey forVaultVersion:vaultVersion error:&error];
		XCTAssertNil(cryptor);
		XCTAssertEqualObjects(kSETOCryptorProviderErrorDomain, error.domain);
		XCTAssertEqual(SETOCryptorProviderUnsupportedVaultFormatError, error.code);
	}
}

@end
