//
//  SETOCryptorV3Tests.m
//  SETOCryptomatorCryptor
//
//  Created by Sebastian Stenzel on 15.02.15.
//  Copyright © 2015-2017 Skymatic. All rights reserved.
//

#import <XCTest/XCTest.h>
#import "SETOCryptor.h"
#import "SETOCryptorProvider.h"
#import "SETOMasterKey.h"

@interface SETOCryptorV3Tests : XCTestCase
@property (nonatomic, strong) SETOCryptor *cryptor;
@end

@implementation SETOCryptorV3Tests

- (void)setUp {
	[super setUp];
	NSString *masterKeyFileContentsStr = @"{\"version\":3,\"scryptSalt\":\"3cKOp+YKt64=\",\"scryptCostParam\":16384,\"scryptBlockSize\":8,\"primaryMasterKey\":\"yAIFYioq0cac6mHDBczjfbjuhSfeEIHFtGpcoR7fQ6h/LlQERnQXzQ==\",\"hmacMasterKey\":\"eSBguTyeLjddkIlyy1gp5zLagKiUUUjxaxUGaX1IeDu1SWEpAPymqQ==\"}";
	NSData *masterKeyFileContents = [masterKeyFileContentsStr dataUsingEncoding:NSUTF8StringEncoding];

	SETOMasterKey *masterKey = [[SETOMasterKey alloc] init];
	XCTAssertTrue([masterKey updateFromJSONData:masterKeyFileContents]);

	NSError *error;
	self.cryptor = [SETOCryptorProvider cryptorFromMasterKey:masterKey withPassword:@"asd" error:&error];
	XCTAssertNotNil(self.cryptor);
	XCTAssertNil(error);
}

#pragma mark - Authentication

- (void)testFileAuthentication {
	XCTestExpectation *authentication1Finished = [self expectationWithDescription:@"authentication of authentic file finished"];
	XCTestExpectation *authentication2Finished = [self expectationWithDescription:@"authentication of unauthentic content file finished"];
	XCTestExpectation *authentication3Finished = [self expectationWithDescription:@"authentication of unauthentic header file finished"];

	// write authentic test data to file:
	NSString *filePath1 = [NSTemporaryDirectory() stringByAppendingPathComponent:@"test1.aes"];
	NSString *encryptedFileString1 = @"8lEJGixRMS3QxPS7+Lfx/n+gu1mbE+zYl4uhyqdmW9V6z7oT72epELVf/KEArykxqTnTxeVs6dl3fsmrrKIqyA4220SEl8bAmQuvZvFInL/gcSw8IvJctgprIZD4zcs+7J4zlvMmQ9Ye9/aa/ch4Bfzb13BnZyM8FKt9SgUMTLcR5CxDDRsu8VhuF5AwVwg1IoGMHA==";
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
	NSString *encryptedFileString2 = @"8lEJGixRMS3QxPS7+Lfx/n+gu1mbE+zYl4uhyqdmW9V6z7oT72epELVf/KEArykxqTnTxeVs6dl3fsmrrKIqyA4220SEl8bAmQuvZvFInL/gcSw8IvJctgprIZD4zcs+7J4zlvMmQ9Ye9/aa/ch4Bfzb13BnZyM8FKt9SgUMTLcR5CxDDRsu8VhuF5AwVwg1IoGMHa==";
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
	NSString *encryptedFileString3 = @"7lEJGixRMS3QxPS7+Lfx/n+gu1mbE+zYl4uhyqdmW9V6z7oT72epELVf/KEArykxqTnTxeVs6dl3fsmrrKIqyA4220SEl8bAmQuvZvFInL/gcSw8IvJctgprIZD4zcs+7J4zlvMmQ9Ye9/aa/ch4Bfzb13BnZyM8FKt9SgUMTLcR5CxDDRsu8VhuF5AwVwg1IoGMHA==";
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
	NSString *encryptedPath = [self.cryptor encryptDirectoryId:@"d77c2569-0b0b-41c1-9d6b-a3fb11933226"];
	XCTAssertTrue([@"HH7I6B3ME5N3ZOHUCLIAGQID5NFYNXGH" isEqualToString:encryptedPath]);
}

#pragma mark - Decryption

- (void)testMasterKeyDecryption {
	NSString *masterKeyFileContentsStr = @"{\"version\":3,\"scryptSalt\":\"3cKOp+YKt64=\",\"scryptCostParam\":16384,\"scryptBlockSize\":8,\"primaryMasterKey\":\"yAIFYioq0cac6mHDBczjfbjuhSfeEIHFtGpcoR7fQ6h/LlQERnQXzQ==\",\"hmacMasterKey\":\"eSBguTyeLjddkIlyy1gp5zLagKiUUUjxaxUGaX1IeDu1SWEpAPymqQ==\"}";
	NSData *masterKeyFileContents = [masterKeyFileContentsStr dataUsingEncoding:NSUTF8StringEncoding];

	SETOMasterKey *masterKey = [[SETOMasterKey alloc] init];
	XCTAssertTrue([masterKey updateFromJSONData:masterKeyFileContents]);
	XCTAssertNotNil([SETOCryptorProvider cryptorFromMasterKey:masterKey withPassword:@"asd" error:nil]);
	XCTAssertNil([SETOCryptorProvider cryptorFromMasterKey:masterKey withPassword:@"asdf" error:nil]);
}

- (void)testDecryption {
	XCTestExpectation *decryptionFinished = [self expectationWithDescription:@"decryption of file finished"];

	// write authentic test data to file:
	NSString *fileInPath1 = [NSTemporaryDirectory() stringByAppendingPathComponent:@"test1.aes"];
	NSString *fileOutPath1 = [NSTemporaryDirectory() stringByAppendingPathComponent:@"test1.txt"];
	NSString *encryptedFileString1 = @"8lEJGixRMS3QxPS7+Lfx/n+gu1mbE+zYl4uhyqdmW9V6z7oT72epELVf/KEArykxqTnTxeVs6dl3fsmrrKIqyA4220SEl8bAmQuvZvFInL/gcSw8IvJctgprIZD4zcs+7J4zlvMmQ9Ye9/aa/ch4Bfzb13BnZyM8FKt9SgUMTLcR5CxDDRsu8VhuF5AwVwg1IoGMHA==";
	NSData *encryptedFileData1 = [[NSData alloc] initWithBase64EncodedString:encryptedFileString1 options:0];
	[encryptedFileData1 writeToFile:fileInPath1 atomically:YES];
	[self.cryptor decryptFileAtPath:fileInPath1 toPath:fileOutPath1 callback:^(NSError *error) {
		XCTAssertNil(error);
		
		NSData *decrypted = [NSData dataWithContentsOfFile:fileOutPath1];
		NSString *cleartext = [[NSString alloc] initWithData:decrypted encoding:NSUTF8StringEncoding];
		XCTAssertTrue([@"setoLabs ftw" isEqualToString:cleartext]);
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

	NSString *largeCiphertextPath = [[NSBundle bundleForClass:[self class]] pathForResource:@"ciphertext_v3" ofType:@"aes"];
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
	NSString *foo = @"YRDHTXQIW5VLBRHCBKDJJUQ5RQ3ZQY524DT3FYG6NVFSEYMYXMURYF2OMFSVQDAWNEML5XD7TMXYETWVSACXIQZF637LAJP7Q2NJU6Q=";
	NSString *decrypted = [self.cryptor decryptFilename:foo insideDirectoryWithId:@"63fb3905-9de6-4e0d-9cde-c6494cd6e0ad"];
	XCTAssertEqualObjects(decrypted, @"So oder so ähnlich könnte Ihr Ordner heißen");
}

#pragma mark - Encryption & Decryption

- (void)testEncryptionAndDecryptionOfPathComponents {
	NSString *cleartextPathComponent = @"So oder so ähnlich könnte Ihr Ordner heißen";
	NSString *ciphertextPathComponent = [self.cryptor encryptFilename:cleartextPathComponent insideDirectoryWithId:@"63fb3905-9de6-4e0d-9cde-c6494cd6e0ad"];
	NSString *decrypted = [self.cryptor decryptFilename:ciphertextPathComponent insideDirectoryWithId:@"63fb3905-9de6-4e0d-9cde-c6494cd6e0ad"];
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

@end
