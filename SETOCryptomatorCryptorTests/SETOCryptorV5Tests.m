//
//  SETOCryptorV5Tests.m
//  SETOCryptomatorCryptor
//
//  Created by Tobias Hagemann on 02/09/16.
//  Copyright © 2015-2016 setoLabs. All rights reserved.
//

#import <XCTest/XCTest.h>
#import "SETOCryptor.h"
#import "SETOCryptorProvider.h"
#import "SETOMasterKey.h"

@interface SETOCryptorV5Tests : XCTestCase
@property (nonatomic, strong) SETOCryptor *cryptor;
@end

@implementation SETOCryptorV5Tests

- (void)setUp {
	[super setUp];
	NSString *masterKeyFileContentsStr = @"{\"scryptSalt\":\"IQ3dNx9mQzk=\",\"scryptCostParam\":16384,\"scryptBlockSize\":8,\"primaryMasterKey\":\"FeOTDrO2fnm4vfjfsp8EirlWt+4VBeuUhLN23Ssq0QFvS8ZR2FNkbw==\",\"hmacMasterKey\":\"FRm3SD8K4ubsxP9PQVOi17WXbesKrp+mP4NnCQGED2aFTxr2bXd/Fw==\",\"versionMac\":\"VV80Uz49sJfQ9o+evVj4AtBs2scg4PbKx3ZgMp6o30g=\",\"version\":5}";
	NSData *masterKeyFileContents = [masterKeyFileContentsStr dataUsingEncoding:NSUTF8StringEncoding];

	SETOMasterKey *masterKey = [[SETOMasterKey alloc] init];
	XCTAssertTrue([masterKey updateFromJSONData:masterKeyFileContents]);

	NSError *error;
	self.cryptor = [SETOCryptorProvider cryptorFromMasterKey:masterKey withPassword:@"qwe" error:&error];
	XCTAssertNotNil(self.cryptor);
	XCTAssertNil(error);
}

- (void)testDifferentNormalizationFormsOfPassword {
	NSString *masterKeyFileContentsStr = @"{\"scryptSalt\":\"xjkJmSgJ/zU=\",\"scryptCostParam\":16384,\"scryptBlockSize\":8,\"primaryMasterKey\":\"3BvylqppBfNQ+ZJNS+wRbSKutuHT3AGGIY3IT0yMzpSSBfS+pr6WIw==\",\"hmacMasterKey\":\"pienjdRNu5PY4ZY8sM/CwGMZGVZ4YmO4MjXwSYYEaiy13/Qm0NoAcA==\",\"versionMac\":\"8ArW2fJ4Tdi0NjqNPw+QngU3YLX009G7ZplJi+7kQxo=\",\"version\":5}";
	NSData *masterKeyFileContents = [masterKeyFileContentsStr dataUsingEncoding:NSUTF8StringEncoding];

	SETOMasterKey *masterKey = [[SETOMasterKey alloc] init];
	XCTAssertTrue([masterKey updateFromJSONData:masterKeyFileContents]);

	NSError *error1;
	XCTAssertNotNil([SETOCryptorProvider cryptorFromMasterKey:masterKey withPassword:@"țț" error:&error1]); // NFC + NFD
	XCTAssertNil(error1);

	NSError *error2;
	XCTAssertNil([SETOCryptorProvider cryptorFromMasterKey:masterKey withPassword:@"țț" error:&error2]); // NFC + NFC
	XCTAssertEqual(error2.domain, kSETOCryptorProviderErrorDomain);
	XCTAssertEqual(error2.code, SETOCryptorProviderInvalidPasswordError);

	NSError *error3;
	XCTAssertNil([SETOCryptorProvider cryptorFromMasterKey:masterKey withPassword:@"țț" error:&error3]); // NFD + NFD
	XCTAssertEqual(error3.domain, kSETOCryptorProviderErrorDomain);
	XCTAssertEqual(error3.code, SETOCryptorProviderInvalidPasswordError);

	NSError *error4;
	XCTAssertNil([SETOCryptorProvider cryptorFromMasterKey:masterKey withPassword:@"țț" error:&error4]); // NFD + NFC
	XCTAssertEqual(error4.domain, kSETOCryptorProviderErrorDomain);
	XCTAssertEqual(error4.code, SETOCryptorProviderInvalidPasswordError);
}

#pragma mark - Authentication

- (void)testUnauthenticMasterKeyVersion {
	NSString *masterKeyFileContentsStr = @"{\"scryptSalt\":\"IQ3dNx9mQzk=\",\"scryptCostParam\":16384,\"scryptBlockSize\":8,\"primaryMasterKey\":\"FeOTDrO2fnm4vfjfsp8EirlWt+4VBeuUhLN23Ssq0QFvS8ZR2FNkbw==\",\"hmacMasterKey\":\"FRm3SD8K4ubsxP9PQVOi17WXbesKrp+mP4NnCQGED2aFTxr2bXd/Fw==\",\"versionMac\":\"VV80Uz49sJfQ9o+evVj4AtBs2scg4PbKx3ZgMp6o30a=\",\"version\":5}";
	NSData *masterKeyFileContents = [masterKeyFileContentsStr dataUsingEncoding:NSUTF8StringEncoding];

	SETOMasterKey *masterKey = [[SETOMasterKey alloc] init];
	XCTAssertTrue([masterKey updateFromJSONData:masterKeyFileContents]);
	NSError *error;
	XCTAssertNil([SETOCryptorProvider cryptorFromMasterKey:masterKey withPassword:@"qwe" error:&error]);
	XCTAssertEqual(error.domain, kSETOCryptorProviderErrorDomain);
	XCTAssertEqual(error.code, SETOCryptorProviderUnauthenticKeyVersionError);
}

- (void)testFileAuthentication {
	XCTestExpectation *authentication1Finished = [self expectationWithDescription:@"authentication of authentic file finished"];
	XCTestExpectation *authentication2Finished = [self expectationWithDescription:@"authentication of unauthentic content file finished"];
	XCTestExpectation *authentication3Finished = [self expectationWithDescription:@"authentication of unauthentic header file finished"];

	// write authentic test data to file:
	NSString *filePath1 = [NSTemporaryDirectory() stringByAppendingPathComponent:@"test1.aes"];
	NSString *encryptedFileString1 = @"2HrK7wEaE49Q52Y3b38CkcZpKV+8WQLDk+djHO+xUmu8XiHfD6XOwdO9iSsyvJnQTQsx9TRBZoQ16W32Bpu/6zXyDBMP0xaUwNtqWq8FWIhAqwCf2w+3oHd3E0AB2Qb/wn52zvGeb1sNZF3+1BWpTP9hsAzzqBr94QhlEt8BxOjc5sr+lu939sHil6c6w2i3kDaG";
	NSData *encryptedFileData1 = [[NSData alloc] initWithBase64EncodedString:encryptedFileString1 options:0];
	[encryptedFileData1 writeToFile:filePath1 atomically:YES];
	[self.cryptor authenticateFileAtPath:filePath1 callback:^(NSError *error) {
		XCTAssertNil(error);
		
		[[NSFileManager defaultManager] removeItemAtPath:filePath1 error:NULL];
		
		[authentication1Finished fulfill];
	} progress:^(CGFloat progress) {
		NSLog(@"authentication progress 1: %.2f", progress);
		// ignore
	}];

	// write unauthentic content test data to file:
	NSString *filePath2 = [NSTemporaryDirectory() stringByAppendingPathComponent:@"test2.aes"];
	NSString *encryptedFileString2 = @"2HrK7wEaE49Q52Y3b38CkcZpKV+8WQLDk+djHO+xUmu8XiHfD6XOwdO9iSsyvJnQTQsx9TRBZoQ16W32Bpu/6zXyDBMP0xaUwNtqWq8FWIhAqwCftw+3oHd3E0AB2Qb/wn52zvGeb1sNZF3+1BWpTP9hsAzzqBr94QhlEt8BxOjc5sr+lu939sHil6c6w2i3kDaG";
	NSData *encryptedFileData2 = [[NSData alloc] initWithBase64EncodedString:encryptedFileString2 options:0];
	[encryptedFileData2 writeToFile:filePath2 atomically:YES];
	[self.cryptor authenticateFileAtPath:filePath2 callback:^(NSError *error) {
		XCTAssertNotNil(error);
		
		[[NSFileManager defaultManager] removeItemAtPath:filePath2 error:NULL];
		
		[authentication2Finished fulfill];
	} progress:^(CGFloat progress) {
		NSLog(@"authentication progress 2: %.2f", progress);
		// ignore
	}];

	// write unauthentic header test data to file:
	NSString *filePath3 = [NSTemporaryDirectory() stringByAppendingPathComponent:@"test3.aes"];
	NSString *encryptedFileString3 = @"2HrK7wEaE49Q52Y3b38CkcZpKv+8WQLDk+djHO+xUmu8XiHfD6XOwdO9iSsyvJnQTQsx9TRBZoQ16W32Bpu/6zXyDBMP0xaUwNtqWq8FWIhAqwCf2w+3oHd3E0AB2Qb/wn52zvGeb1sNZF3+1BWpTP9hsAzzqBr94QhlEt8BxOjc5sr+lu939sHil6c6w2i3kDaG";
	NSData *encryptedFileData3 = [[NSData alloc] initWithBase64EncodedString:encryptedFileString3 options:0];
	[encryptedFileData3 writeToFile:filePath3 atomically:YES];
	[self.cryptor authenticateFileAtPath:filePath3 callback:^(NSError *error) {
		XCTAssertNotNil(error);
		
		[[NSFileManager defaultManager] removeItemAtPath:filePath3 error:NULL];
		
		[authentication3Finished fulfill];
	} progress:^(CGFloat progress) {
		NSLog(@"authentication progress 3: %.2f", progress);
		// ignore
	}];

	[self waitForExpectationsWithTimeout:0.5 handler:nil];
}

#pragma mark - Encryption

- (void)testDirectoryIdEncryption {
	NSString *encryptedPath = [self.cryptor encryptDirectoryId:@"e332c87c-70c6-4054-a256-543624585fd7"];
	XCTAssertTrue([@"IQKGLSTJ52Z6LRKV2XYIUCF3PV2BDN66" isEqualToString:encryptedPath]);
}

#pragma mark - Decryption

- (void)testMasterKeyDecryption {
	NSString *masterKeyFileContentsStr = @"{\"scryptSalt\":\"IQ3dNx9mQzk=\",\"scryptCostParam\":16384,\"scryptBlockSize\":8,\"primaryMasterKey\":\"FeOTDrO2fnm4vfjfsp8EirlWt+4VBeuUhLN23Ssq0QFvS8ZR2FNkbw==\",\"hmacMasterKey\":\"FRm3SD8K4ubsxP9PQVOi17WXbesKrp+mP4NnCQGED2aFTxr2bXd/Fw==\",\"versionMac\":\"VV80Uz49sJfQ9o+evVj4AtBs2scg4PbKx3ZgMp6o30g=\",\"version\":5}";
	NSData *masterKeyFileContents = [masterKeyFileContentsStr dataUsingEncoding:NSUTF8StringEncoding];

	SETOMasterKey *masterKey = [[SETOMasterKey alloc] init];
	XCTAssertTrue([masterKey updateFromJSONData:masterKeyFileContents]);
	XCTAssertNotNil([SETOCryptorProvider cryptorFromMasterKey:masterKey withPassword:@"qwe" error:nil]);
	XCTAssertNil([SETOCryptorProvider cryptorFromMasterKey:masterKey withPassword:@"qwer" error:nil]);
}

- (void)testDecryption {
	XCTestExpectation *decryptionFinished = [self expectationWithDescription:@"decryption of file finished"];

	// write authentic test data to file:
	NSString *fileInPath1 = [NSTemporaryDirectory() stringByAppendingPathComponent:@"test1.aes"];
	NSString *fileOutPath1 = [NSTemporaryDirectory() stringByAppendingPathComponent:@"test1.txt"];
	NSString *encryptedFileString1 = @"2HrK7wEaE49Q52Y3b38CkcZpKV+8WQLDk+djHO+xUmu8XiHfD6XOwdO9iSsyvJnQTQsx9TRBZoQ16W32Bpu/6zXyDBMP0xaUwNtqWq8FWIhAqwCf2w+3oHd3E0AB2Qb/wn52zvGeb1sNZF3+1BWpTP9hsAzzqBr94QhlEt8BxOjc5sr+lu939sHil6c6w2i3kDaG";
	NSData *encryptedFileData1 = [[NSData alloc] initWithBase64EncodedString:encryptedFileString1 options:0];
	[encryptedFileData1 writeToFile:fileInPath1 atomically:YES];
	[self.cryptor decryptFileAtPath:fileInPath1 toPath:fileOutPath1 callback:^(NSError *error) {
		XCTAssertNil(error);
		
		NSData *decrypted = [NSData dataWithContentsOfFile:fileOutPath1];
		NSString *cleartext = [[NSString alloc] initWithData:decrypted encoding:NSUTF8StringEncoding];
		XCTAssertTrue([@"hello world" isEqualToString:cleartext]);
		[[NSFileManager defaultManager] removeItemAtPath:fileInPath1 error:NULL];
		[[NSFileManager defaultManager] removeItemAtPath:fileOutPath1 error:NULL];
		
		[decryptionFinished fulfill];
	} progress:^(CGFloat progress) {
		NSLog(@"decryption progress: %.2f", progress);
		// ignore
	}];

	[self waitForExpectationsWithTimeout:0.5 handler:nil];
}

- (void)testLargeFileDecryption {
	XCTestExpectation *decryptionFinished = [self expectationWithDescription:@"decryption of file finished"];

	NSString *largeCiphertextPath = [[NSBundle bundleForClass:[self class]] pathForResource:@"ciphertext_v5" ofType:@"aes"];
	NSString *fileOutPath = [NSTemporaryDirectory() stringByAppendingPathComponent:@"cleartext.jpg"];

	[self.cryptor decryptFileAtPath:largeCiphertextPath toPath:fileOutPath callback:^(NSError *error) {
		XCTAssertNil(error);
		
		NSString *largeCleartextPath = [[NSBundle bundleForClass:[self class]] pathForResource:@"cleartext" ofType:@"jpg"];
		XCTAssertTrue([[NSFileManager defaultManager] contentsEqualAtPath:fileOutPath andPath:largeCleartextPath]);
		[[NSFileManager defaultManager] removeItemAtPath:fileOutPath error:NULL];
		
		[decryptionFinished fulfill];
	} progress:^(CGFloat progress) {
		NSLog(@"encryption progress: %.2f", progress);
		// ignore
	}];

	[self waitForExpectationsWithTimeout:1.0 handler:nil];
}

- (void)testFancyUnicodeFoldernameDecryption {
	NSString *foo = @"EWQR5HC36SSEBHEWL6LKDDWZSIAJQNY57SJRRNEZU2TMHYW3TKJROAVELZBDI3GBMY4IIZ3CUGZ2BGXLNPZXM5YY7AA5JDEI5XBQ====";
	NSString *decrypted = [self.cryptor decryptFilename:foo insideDirectoryWithId:@"e332c87c-70c6-4054-a256-543624585fd7"];
	XCTAssertEqualObjects(decrypted, @"So oder so ähnlich könnte Ihr Ordner heißen");
}

#pragma mark - Encryption & Decryption

- (void)testEncryptionAndDecryptionOfPathComponents {
	NSString *cleartextPathComponent = @"So oder so ähnlich könnte Ihr Ordner heißen";
	NSString *ciphertextPathComponent = [self.cryptor encryptFilename:cleartextPathComponent insideDirectoryWithId:@"e332c87c-70c6-4054-a256-543624585fd7"];
	NSString *decrypted = [self.cryptor decryptFilename:ciphertextPathComponent insideDirectoryWithId:@"e332c87c-70c6-4054-a256-543624585fd7"];
	XCTAssertEqualObjects(cleartextPathComponent, decrypted);
}

- (void)testEncryptionAndDecryptionWithNewMasterKey {
	// create key:
	SETOCryptor *cryptor = [SETOCryptorProvider newCryptor];
	XCTAssertNotNil(cryptor);
	SETOMasterKey *key = [cryptor masterKeyWithPassword:@"asd"];
	XCTAssertNotNil(key);

	// encrypt:
	XCTestExpectation *encryptionFinished = [self expectationWithDescription:@"encryption of file finished"];
	NSString *fileInPath1 = [NSTemporaryDirectory() stringByAppendingPathComponent:@"test1.txt"];
	NSString *fileOutPath1 = [NSTemporaryDirectory() stringByAppendingPathComponent:@"test1.aes"];
	NSString *cleartextFileString1 = @"Wie macht der Uhu? Woot, woot!";
	NSData *cleartextFileData1 = [cleartextFileString1 dataUsingEncoding:NSUTF8StringEncoding];
	[cleartextFileData1 writeToFile:fileInPath1 atomically:YES];
	[cryptor encryptFileAtPath:fileInPath1 toPath:fileOutPath1 callback:^(NSError *error) {
		XCTAssertNil(error);
		
		[[NSFileManager defaultManager] removeItemAtPath:fileInPath1 error:NULL];
		
		[encryptionFinished fulfill];
	} progress:^(CGFloat progress) {
		NSLog(@"encryption progress: %.2f", progress);
		// ignore
	}];

	[self waitForExpectationsWithTimeout:0.5 handler:nil];

	// authenticate:
	XCTestExpectation *authenticationFinished = [self expectationWithDescription:@"authentication of authentic file finished"];
	[cryptor authenticateFileAtPath:fileOutPath1 callback:^(NSError *error) {
		XCTAssertNil(error);
		[authenticationFinished fulfill];
	} progress:^(CGFloat progress) {
		NSLog(@"authentication progress: %.2f", progress);
		// ignore
	}];

	[self waitForExpectationsWithTimeout:0.5 handler:nil];

	// decrypt:
	XCTestExpectation *decryptionFinished = [self expectationWithDescription:@"decryption of file finished"];
	NSString *fileInPath2 = fileOutPath1;
	NSString *fileOutPath2 = [NSTemporaryDirectory() stringByAppendingPathComponent:@"test2.txt"];
	[cryptor decryptFileAtPath:fileInPath2 toPath:fileOutPath2 callback:^(NSError *error) {
		XCTAssertNil(error);
		
		NSData *decrypted = [NSData dataWithContentsOfFile:fileOutPath2];
		NSString *cleartext = [[NSString alloc] initWithData:decrypted encoding:NSUTF8StringEncoding];
		XCTAssertTrue([cleartextFileString1 isEqualToString:cleartext]);
		[[NSFileManager defaultManager] removeItemAtPath:fileInPath2 error:NULL];
		[[NSFileManager defaultManager] removeItemAtPath:fileOutPath2 error:NULL];
		
		[decryptionFinished fulfill];
	} progress:^(CGFloat progress) {
		NSLog(@"decryption progress: %.2f", progress);
		// ignore
	}];

	[self waitForExpectationsWithTimeout:0.5 handler:nil];
}

#pragma mark - Chunk Sizes

- (void)testCleartextSize {
	XCTAssertEqual(0, [SETOCryptorProvider cleartextSizeFromCiphertextSize:0 withCryptor:self.cryptor]);

	XCTAssertEqual(1, [SETOCryptorProvider cleartextSizeFromCiphertextSize:1 + 48 withCryptor:self.cryptor]);
	XCTAssertEqual(32 * 1024 - 1, [SETOCryptorProvider cleartextSizeFromCiphertextSize:32 * 1024 - 1 + 48 withCryptor:self.cryptor]);
	XCTAssertEqual(32 * 1024, [SETOCryptorProvider cleartextSizeFromCiphertextSize:32 * 1024 + 48 withCryptor:self.cryptor]);

	XCTAssertEqual(32 * 1024 + 1, [SETOCryptorProvider cleartextSizeFromCiphertextSize:32 * 1024 + 1 + 48 * 2 withCryptor:self.cryptor]);
	XCTAssertEqual(32 * 1024 + 2, [SETOCryptorProvider cleartextSizeFromCiphertextSize:32 * 1024 + 2 + 48 * 2 withCryptor:self.cryptor]);
	XCTAssertEqual(64 * 1024 - 1, [SETOCryptorProvider cleartextSizeFromCiphertextSize:64 * 1024 - 1 + 48 * 2 withCryptor:self.cryptor]);
	XCTAssertEqual(64 * 1024, [SETOCryptorProvider cleartextSizeFromCiphertextSize:64 * 1024 + 48 * 2 withCryptor:self.cryptor]);

	XCTAssertEqual(64 * 1024 + 1, [SETOCryptorProvider cleartextSizeFromCiphertextSize:64 * 1024 + 1 + 48 * 3 withCryptor:self.cryptor]);
}

- (void)testCleartextSizeWithInvalidCiphertextSize {
	XCTAssertEqual(NSUIntegerMax, [SETOCryptorProvider cleartextSizeFromCiphertextSize:1 withCryptor:self.cryptor]);
	XCTAssertEqual(NSUIntegerMax, [SETOCryptorProvider cleartextSizeFromCiphertextSize:48 withCryptor:self.cryptor]);
	XCTAssertEqual(NSUIntegerMax, [SETOCryptorProvider cleartextSizeFromCiphertextSize:32 * 1024 + 1 + 48 withCryptor:self.cryptor]);
	XCTAssertEqual(NSUIntegerMax, [SETOCryptorProvider cleartextSizeFromCiphertextSize:32 * 1024 + 48 * 2 withCryptor:self.cryptor]);
}

- (void)testCiphertextSize {
	XCTAssertEqual(0, [SETOCryptorProvider ciphertextSizeFromCleartextSize:0 withCryptor:self.cryptor]);

	XCTAssertEqual(1 + 48, [SETOCryptorProvider ciphertextSizeFromCleartextSize:1 withCryptor:self.cryptor]);
	XCTAssertEqual(32 * 1024 - 1 + 48, [SETOCryptorProvider ciphertextSizeFromCleartextSize:32 * 1024 - 1 withCryptor:self.cryptor]);
	XCTAssertEqual(32 * 1024 + 48, [SETOCryptorProvider ciphertextSizeFromCleartextSize:32 * 1024 withCryptor:self.cryptor]);

	XCTAssertEqual(32 * 1024 + 1 + 48 * 2, [SETOCryptorProvider ciphertextSizeFromCleartextSize:32 * 1024 + 1 withCryptor:self.cryptor]);
	XCTAssertEqual(32 * 1024 + 2 + 48 * 2, [SETOCryptorProvider ciphertextSizeFromCleartextSize:32 * 1024 + 2 withCryptor:self.cryptor]);
	XCTAssertEqual(64 * 1024 - 1 + 48 * 2, [SETOCryptorProvider ciphertextSizeFromCleartextSize:64 * 1024 - 1 withCryptor:self.cryptor]);
	XCTAssertEqual(64 * 1024 + 48 * 2, [SETOCryptorProvider ciphertextSizeFromCleartextSize:64 * 1024 withCryptor:self.cryptor]);

	XCTAssertEqual(64 * 1024 + 1 + 48 * 3, [SETOCryptorProvider ciphertextSizeFromCleartextSize:64 * 1024 + 1 withCryptor:self.cryptor]);
}

@end
