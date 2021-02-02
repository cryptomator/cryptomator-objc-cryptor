//
//  SETOMasterKeyFileTests.m
//  SETOCryptomatorCryptorTests
//
//  Created by Tobias Hagemann on 29.01.21.
//  Copyright © 2021 Skymatic. All rights reserved.
//

#import <XCTest/XCTest.h>
#import "SETOMasterKeyFile.h"
#import "SETOMasterKey.h"
#import "SETOSecureRandomMock.h"

// exposing some of SETOMasterKey's properties and methods for testability
@interface SETOMasterKeyFile ()
@property (nonatomic, readonly) NSData *scryptSalt;
@property (nonatomic, readonly) uint64_t scryptCostParam;
@property (nonatomic, readonly) uint32_t scryptBlockSize;
@property (nonatomic, readonly) NSData *primaryMasterKey;
@property (nonatomic, readonly) NSData *macMasterKey;
@property (nonatomic, readonly) NSData *versionMac;

+ (NSData *)lockMasterKey:(SETOMasterKey *)masterKey withVaultVersion:(NSInteger)vaultVersion passphrase:(NSString *)passphrase pepper:(NSData *)pepper scryptCostParam:(uint64_t)scryptCostParam secureRandom:(SETOSecureRandom *)secureRandom error:(NSError **)error;
+ (NSData *)wrapKey:(NSData *)rawKey kek:(unsigned char *)kekBytes error:(NSError **)error;
+ (NSData *)unwrapKey:(NSData *)wrappedKey kek:(unsigned char *)kekBytes error:(NSError **)error;
@end

@interface SETOMasterKeyFileTests : XCTestCase
@end

@implementation SETOMasterKeyFileTests

- (void)testInitialization {
	NSData *jsonData = [@"{\"scryptSalt\":\"AAAAAAAAAAA=\",\"scryptCostParam\":2,\"scryptBlockSize\":8,\"primaryMasterKey\":\"mM+qoQ+o0qvPTiDAZYt+flaC3WbpNAx1sTXaUzxwpy0M9Ctj6Tih/Q==\",\"hmacMasterKey\":\"mM+qoQ+o0qvPTiDAZYt+flaC3WbpNAx1sTXaUzxwpy0M9Ctj6Tih/Q==\",\"versionMac\":\"cn2sAK6l9p1/w9deJVUuW3h7br056mpv5srvALiYw+g=\",\"version\":7}" dataUsingEncoding:NSUTF8StringEncoding];
	SETOMasterKeyFile *masterKeyFile = [[SETOMasterKeyFile alloc] initWithContentFromJSONData:jsonData];
	XCTAssertEqual(7, masterKeyFile.version);
	XCTAssertEqualObjects([[NSData alloc] initWithBase64EncodedString:@"AAAAAAAAAAA=" options:0], masterKeyFile.scryptSalt);
	XCTAssertEqual(2, masterKeyFile.scryptCostParam);
	XCTAssertEqual(8, masterKeyFile.scryptBlockSize);
	XCTAssertEqualObjects([[NSData alloc] initWithBase64EncodedString:@"mM+qoQ+o0qvPTiDAZYt+flaC3WbpNAx1sTXaUzxwpy0M9Ctj6Tih/Q==" options:0], masterKeyFile.primaryMasterKey);
	XCTAssertEqualObjects([[NSData alloc] initWithBase64EncodedString:@"mM+qoQ+o0qvPTiDAZYt+flaC3WbpNAx1sTXaUzxwpy0M9Ctj6Tih/Q==" options:0], masterKeyFile.macMasterKey);
	XCTAssertEqualObjects([[NSData alloc] initWithBase64EncodedString:@"cn2sAK6l9p1/w9deJVUuW3h7br056mpv5srvALiYw+g=" options:0], masterKeyFile.versionMac);
}

- (void)testUnlock {
	NSData *jsonData = [@"{\"scryptSalt\":\"AAAAAAAAAAA=\",\"scryptCostParam\":2,\"scryptBlockSize\":8,\"primaryMasterKey\":\"mM+qoQ+o0qvPTiDAZYt+flaC3WbpNAx1sTXaUzxwpy0M9Ctj6Tih/Q==\",\"hmacMasterKey\":\"mM+qoQ+o0qvPTiDAZYt+flaC3WbpNAx1sTXaUzxwpy0M9Ctj6Tih/Q==\",\"versionMac\":\"cn2sAK6l9p1/w9deJVUuW3h7br056mpv5srvALiYw+g=\",\"version\":7}" dataUsingEncoding:NSUTF8StringEncoding];
	SETOMasterKeyFile *masterKeyFile = [[SETOMasterKeyFile alloc] initWithContentFromJSONData:jsonData];
	NSError *unlockError;
	SETOMasterKey *masterKey = [masterKeyFile unlockWithPassphrase:@"asd" pepper:nil expectedVaultVersion:7 error:&unlockError];
	XCTAssertNotNil(masterKey);
	XCTAssertNil(unlockError);
	unsigned char expectedKeyBuffer[32] = {0};
	XCTAssertEqualObjects([NSData dataWithBytes:expectedKeyBuffer length:sizeof(expectedKeyBuffer)], masterKey.aesMasterKey);
	XCTAssertEqualObjects([NSData dataWithBytes:expectedKeyBuffer length:sizeof(expectedKeyBuffer)], masterKey.macMasterKey);
}

- (void)testUnlockWithWrongPassphrase {
	NSData *jsonData = [@"{\"scryptSalt\":\"AAAAAAAAAAA=\",\"scryptCostParam\":2,\"scryptBlockSize\":8,\"primaryMasterKey\":\"mM+qoQ+o0qvPTiDAZYt+flaC3WbpNAx1sTXaUzxwpy0M9Ctj6Tih/Q==\",\"hmacMasterKey\":\"mM+qoQ+o0qvPTiDAZYt+flaC3WbpNAx1sTXaUzxwpy0M9Ctj6Tih/Q==\",\"versionMac\":\"cn2sAK6l9p1/w9deJVUuW3h7br056mpv5srvALiYw+g=\",\"version\":7}" dataUsingEncoding:NSUTF8StringEncoding];
	SETOMasterKeyFile *masterKeyFile = [[SETOMasterKeyFile alloc] initWithContentFromJSONData:jsonData];
	NSError *unlockError;
	SETOMasterKey *masterKey = [masterKeyFile unlockWithPassphrase:@"qwe" pepper:nil expectedVaultVersion:7 error:&unlockError];
	XCTAssertNil(masterKey);
	XCTAssertEqualObjects(unlockError.domain, kSETOMasterKeyFileErrorDomain);
	XCTAssertEqual(unlockError.code, SETOMasterKeyFileInvalidPassphraseError);
}

- (void)testUnlockWithInvalidVersionMac {
	NSData *jsonData = [@"{\"scryptSalt\":\"AAAAAAAAAAA=\",\"scryptCostParam\":2,\"scryptBlockSize\":8,\"primaryMasterKey\":\"mM+qoQ+o0qvPTiDAZYt+flaC3WbpNAx1sTXaUzxwpy0M9Ctj6Tih/Q==\",\"hmacMasterKey\":\"mM+qoQ+o0qvPTiDAZYt+flaC3WbpNAx1sTXaUzxwpy0M9Ctj6Tih/Q==\",\"versionMac\":\"cn2sAK6l9p1/w9deJVUuW3h7br056mpv5srvALiYw+G=\",\"version\":7}" dataUsingEncoding:NSUTF8StringEncoding];
	SETOMasterKeyFile *masterKeyFile = [[SETOMasterKeyFile alloc] initWithContentFromJSONData:jsonData];
	NSError *unlockError;
	SETOMasterKey *masterKey = [masterKeyFile unlockWithPassphrase:@"asd" pepper:nil expectedVaultVersion:7 error:&unlockError];
	XCTAssertNil(masterKey);
	XCTAssertEqualObjects(unlockError.domain, kSETOMasterKeyFileErrorDomain);
	XCTAssertEqual(unlockError.code, SETOMasterKeyFileMalformedError);
}

- (void)testUnlockWithMalformedJson1 {
	NSData *jsonData = [@"{\"scryptSalt\":\"AAAAAAAAAAA=\",\"scryptCostParam\":2,\"scryptBlockSize\":8,\"primaryMasterKey\":\"mM+qoQ+o0qvPTiDAZYt+flaC3WbpNAx1sTXaUzxwpy0M9Ctj6Tih/Q!!\",\"hmacMasterKey\":\"mM+qoQ+o0qvPTiDAZYt+flaC3WbpNAx1sTXaUzxwpy0M9Ctj6Tih/Q==\",\"versionMac\":\"cn2sAK6l9p1/w9deJVUuW3h7br056mpv5srvALiYw+g=\",\"version\":7}" dataUsingEncoding:NSUTF8StringEncoding];
	SETOMasterKeyFile *masterKeyFile = [[SETOMasterKeyFile alloc] initWithContentFromJSONData:jsonData];
	NSError *unlockError;
	SETOMasterKey *masterKey = [masterKeyFile unlockWithPassphrase:@"asd" pepper:nil expectedVaultVersion:7 error:&unlockError];
	XCTAssertNil(masterKey);
	XCTAssertEqualObjects(unlockError.domain, kSETOMasterKeyFileErrorDomain);
	XCTAssertEqual(unlockError.code, SETOMasterKeyFileMalformedError);
}

- (void)testUnlockWithMalformedJson2 {
	NSData *jsonData = [@"{\"scryptSalt\":\"AAAAAAAAAAA=\",\"scryptCostParam\":2,\"scryptBlockSize\":8,\"primaryMasterKey\":\"mM+qoQ+o0qvPTiDAZYt+flaC3WbpNAx1sTXaUzxwpy0M9Ctj6Tih/Q==\",\"hmacMasterKey\":\"mM+qoQ+o0qvPTiDAZYt+flaC3WbpNAx1sTXaUzxwpy0M9Ctj6Tih/Q!!\",\"versionMac\":\"cn2sAK6l9p1/w9deJVUuW3h7br056mpv5srvALiYw+g=\",\"version\":7}" dataUsingEncoding:NSUTF8StringEncoding];
	SETOMasterKeyFile *masterKeyFile = [[SETOMasterKeyFile alloc] initWithContentFromJSONData:jsonData];
	NSError *unlockError;
	SETOMasterKey *masterKey = [masterKeyFile unlockWithPassphrase:@"asd" pepper:nil expectedVaultVersion:7 error:&unlockError];
	XCTAssertNil(masterKey);
	XCTAssertEqualObjects(unlockError.domain, kSETOMasterKeyFileErrorDomain);
	XCTAssertEqual(unlockError.code, SETOMasterKeyFileMalformedError);
}

- (void)testUnlockWithMalformedJson3 {
	NSData *jsonData = [@"{\"scryptSalt\":\"AAAAAAAAAAA=\",\"scryptCostParam\":2,\"scryptBlockSize\":8,\"primaryMasterKey\":\"mM+qoQ+o0qvPTiDAZYt+flaC3WbpNAx1sTXaUzxwpy0M9Ctj6Tih/Q==\",\"hmacMasterKey\":\"mM+qoQ+o0qvPTiDAZYt+flaC3WbpNAx1sTXaUzxwpy0M9Ctj6Tih/Q==\",\"versionMac\":\"cn2sAK6l\",\"version\":7}" dataUsingEncoding:NSUTF8StringEncoding];
	SETOMasterKeyFile *masterKeyFile = [[SETOMasterKeyFile alloc] initWithContentFromJSONData:jsonData];
	NSError *unlockError;
	SETOMasterKey *masterKey = [masterKeyFile unlockWithPassphrase:@"asd" pepper:nil expectedVaultVersion:7 error:&unlockError];
	XCTAssertNil(masterKey);
	XCTAssertEqualObjects(unlockError.domain, kSETOMasterKeyFileErrorDomain);
	XCTAssertEqual(unlockError.code, SETOMasterKeyFileMalformedError);
}

- (void)testUnlockWithDifferentNormalizationFormsOfPassphrase {
	NSData *jsonData = [@"{\"scryptSalt\":\"xjkJmSgJ/zU=\",\"scryptCostParam\":16384,\"scryptBlockSize\":8,\"primaryMasterKey\":\"3BvylqppBfNQ+ZJNS+wRbSKutuHT3AGGIY3IT0yMzpSSBfS+pr6WIw==\",\"hmacMasterKey\":\"pienjdRNu5PY4ZY8sM/CwGMZGVZ4YmO4MjXwSYYEaiy13/Qm0NoAcA==\",\"versionMac\":\"8ArW2fJ4Tdi0NjqNPw+QngU3YLX009G7ZplJi+7kQxo=\",\"version\":5}" dataUsingEncoding:NSUTF8StringEncoding];
	SETOMasterKeyFile *masterKeyFile = [[SETOMasterKeyFile alloc] initWithContentFromJSONData:jsonData];

	NSError *unlockError1;
	XCTAssertNotNil([masterKeyFile unlockWithPassphrase:@"țț" pepper:nil expectedVaultVersion:5 error:&unlockError1]); // NFC + NFD
	XCTAssertNil(unlockError1);

	NSError *unlockError2;
	XCTAssertNil([masterKeyFile unlockWithPassphrase:@"țț" pepper:nil expectedVaultVersion:5 error:&unlockError2]); // NFC + NFC
	XCTAssertEqual(unlockError2.domain, kSETOMasterKeyFileErrorDomain);
	XCTAssertEqual(unlockError2.code, SETOMasterKeyFileInvalidPassphraseError);

	NSError *unlockError3;
	XCTAssertNil([masterKeyFile unlockWithPassphrase:@"țț" pepper:nil expectedVaultVersion:5 error:&unlockError3]); // NFD + NFD
	XCTAssertEqual(unlockError3.domain, kSETOMasterKeyFileErrorDomain);
	XCTAssertEqual(unlockError3.code, SETOMasterKeyFileInvalidPassphraseError);

	NSError *unlockError4;
	XCTAssertNil([masterKeyFile unlockWithPassphrase:@"țț" pepper:nil expectedVaultVersion:5 error:&unlockError4]); // NFD + NFC
	XCTAssertEqual(unlockError4.domain, kSETOMasterKeyFileErrorDomain);
	XCTAssertEqual(unlockError4.code, SETOMasterKeyFileInvalidPassphraseError);
}

- (void)testLock {
	unsigned char aesMasterKeyBuffer[] = {[0 ... 31] = 0x55};
	NSData *aesMasterKey = [NSData dataWithBytes:aesMasterKeyBuffer length:sizeof(aesMasterKeyBuffer)];
	unsigned char macMasterKeyBuffer[] = {[0 ... 31] = 0x77};
	NSData *macMasterKey = [NSData dataWithBytes:macMasterKeyBuffer length:sizeof(macMasterKeyBuffer)];
	SETOMasterKey *masterKey = [[SETOMasterKey alloc] initWithAESMasterKey:aesMasterKey macMasterkey:macMasterKey];
	NSError *lockError;
	NSData *jsonData = [SETOMasterKeyFile lockMasterKey:masterKey withVaultVersion:7 passphrase:@"asd" pepper:nil scryptCostParam:2 secureRandom:[[SETOSecureRandomMock alloc] init] error:&lockError];
	XCTAssertNotNil(jsonData);
	XCTAssertNil(lockError);

	NSError *jsonError;
	NSDictionary *jsonDict = [NSJSONSerialization JSONObjectWithData:jsonData options:0 error:&jsonError];
	XCTAssertNotNil(jsonDict);
	XCTAssertNil(jsonError);
	XCTAssertEqual(7, [jsonDict[@"version"] integerValue]);
	XCTAssertEqualObjects(@"8PDw8PDw8PA=", jsonDict[@"scryptSalt"]);
	XCTAssertEqual(2, [jsonDict[@"scryptCostParam"] integerValue]);
	XCTAssertEqual(8, [jsonDict[@"scryptBlockSize"] integerValue]);
	XCTAssertEqualObjects(@"jvdghkTc01VISrFly37pgaT/UKtXrDCvZcU3tT9Y98zyzn/pJ91bxw==", jsonDict[@"primaryMasterKey"]);
	XCTAssertEqualObjects(@"99I+J4bT3rVpZE8yZwKRV9gHVRmQ8XQEujAL9IuwLTc2D3mg5JEjKA==", jsonDict[@"hmacMasterKey"]);
	XCTAssertEqualObjects(@"sAWFgFNhmtMPeNWr4zh+9Ps7GOtT0pknX11PRQ7eC9Q=", jsonDict[@"versionMac"]);
}

- (void)testLockWithDifferentPeppers {
	unsigned char aesMasterKeyBuffer[] = {[0 ... 31] = 0x55};
	NSData *aesMasterKey = [NSData dataWithBytes:aesMasterKeyBuffer length:sizeof(aesMasterKeyBuffer)];
	unsigned char macMasterKeyBuffer[] = {[0 ... 31] = 0x77};
	NSData *macMasterKey = [NSData dataWithBytes:macMasterKeyBuffer length:sizeof(macMasterKeyBuffer)];
	SETOMasterKey *masterKey = [[SETOMasterKey alloc] initWithAESMasterKey:aesMasterKey macMasterkey:macMasterKey];
	unsigned char pepper1[] = {0x01};
	NSError *lockError1;
	NSData *jsonData1 = [SETOMasterKeyFile lockMasterKey:masterKey withVaultVersion:7 passphrase:@"asd" pepper:[NSData dataWithBytes:pepper1 length:sizeof(pepper1)] scryptCostParam:2 error:&lockError1];
	XCTAssertNil(lockError1);
	unsigned char pepper2[] = {0x02};
	NSError *lockError2;
	NSData *jsonData2 = [SETOMasterKeyFile lockMasterKey:masterKey withVaultVersion:7 passphrase:@"asd" pepper:[NSData dataWithBytes:pepper2 length:sizeof(pepper2)] scryptCostParam:2 error:&lockError2];
	XCTAssertNil(lockError2);
	XCTAssertNotEqualObjects(jsonData1, jsonData2);
}

- (void)testWrapAndUnwrapKey {
	unsigned char keyBuffer[] = {[0 ... 31] = 0x77};
	NSData *key = [NSData dataWithBytes:keyBuffer length:sizeof(keyBuffer)];
	unsigned char kekBytes[] = {[0 ... 31] = 0x55};
	NSError *keyWrapError;
	NSData *wrapped = [SETOMasterKeyFile wrapKey:key kek:kekBytes error:&keyWrapError];
	XCTAssertNil(keyWrapError);
	XCTAssertNotNil(wrapped);
	NSError *keyUnwrapError;
	NSData *unwrapped = [SETOMasterKeyFile unwrapKey:wrapped kek:kekBytes error:&keyUnwrapError];
	XCTAssertNil(keyUnwrapError);
	XCTAssertNotNil(unwrapped);
}

- (void)testWrapKeyWithInvalidKey {
	unsigned char keyBuffer[] = {[0 ... 17] = 0x77};
	NSData *key = [NSData dataWithBytes:keyBuffer length:sizeof(keyBuffer)];
	unsigned char kekBytes[] = {[0 ... 31] = 0x55};
	NSError *keyWrapError;
	NSData *wrapped = [SETOMasterKeyFile wrapKey:key kek:kekBytes error:&keyWrapError];
	XCTAssertNil(wrapped);
	XCTAssertEqualObjects(keyWrapError.domain, kSETOMasterKeyFileErrorDomain);
	XCTAssertEqual(keyWrapError.code, SETOMasterKeyFileKeyWrapFailedError);
}

@end
