//
//  SETOCryptorV7Tests.m
//  SETOCryptomatorCryptor
//
//  Created by Tobias Hagemann on 13.09.19.
//  Copyright © 2019 Skymatic. All rights reserved.
//

#import <XCTest/XCTest.h>
#import "SETOCryptor.h"
#import "SETOCryptorProvider.h"
#import "SETOMasterKey.h"

@interface SETOCryptorV7Tests : XCTestCase
@property (nonatomic, strong) SETOCryptor *cryptor;
@end

@implementation SETOCryptorV7Tests

- (void)setUp {
	[super setUp];
	NSString *masterKeyFileContentsStr = @"{\"scryptSalt\":\"7lVfBkGtwBk=\",\"scryptCostParam\":32768,\"scryptBlockSize\":8,\"primaryMasterKey\":\"X66+OaJnb2ZkK4ZcMh+Ak2dAI1W0GxF3GLjoFvvYd9JUoZbtXE0l8w==\",\"hmacMasterKey\":\"wasdO4481tftpBRgrY1rdzFq+0QAB9aCRyQ8D5kYrAo//NuwYljkYg==\",\"versionMac\":\"QEEtUgSk+sUypf9TeEOmU/PG/J2zx/BuRJXpbgsh3fk=\",\"version\":7}";
	NSData *masterKeyFileContents = [masterKeyFileContentsStr dataUsingEncoding:NSUTF8StringEncoding];

	SETOMasterKey *masterKey = [[SETOMasterKey alloc] init];
	XCTAssertTrue([masterKey updateFromJSONData:masterKeyFileContents]);

	NSError *error;
	self.cryptor = [SETOCryptorProvider cryptorFromMasterKey:masterKey withPassword:@"qwe" error:&error];
	XCTAssertNotNil(self.cryptor);
	XCTAssertNil(error);
}

#pragma mark - Encryption

- (void)testFilenameEncryption {
	NSString *cleartext = @"WELCOME TO YOUR VAULT.rtf";
	NSString *ciphertext = [self.cryptor encryptFilename:cleartext insideDirectoryWithId:@""];
	XCTAssertEqualObjects(ciphertext, @"AkUvrvKgAJSYRgZzsyf5Fqp7MdJQQeE_GIjpiFINltrHhqNkSTtWA1I=");
}

#pragma mark - Decryption

- (void)testFilenameDecryption {
	NSString *ciphertext = @"AkUvrvKgAJSYRgZzsyf5Fqp7MdJQQeE_GIjpiFINltrHhqNkSTtWA1I=";
	NSString *cleartext = [self.cryptor decryptFilename:ciphertext insideDirectoryWithId:@""];
	XCTAssertEqualObjects(cleartext, @"WELCOME TO YOUR VAULT.rtf");
}

@end
