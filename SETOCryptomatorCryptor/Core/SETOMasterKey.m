//
//  SETOMasterKey.m
//  SETOCryptomatorCryptor
//
//  Created by Tobias Hagemann on 21.02.15.
//  Copyright © 2015-2017 Skymatic. All rights reserved.
//

#import "SETOMasterKey.h"

#import <KZPropertyMapper/KZPropertyMapper.h>

NSString *const kSETOMasterKeyVersionKey = @"version";
NSString *const kSETOMasterKeyVersionMacKey = @"versionMac";
NSString *const kSETOMasterKeyScryptSaltKey = @"scryptSalt";
NSString *const kSETOMasterKeyScryptCostParamKey = @"scryptCostParam";
NSString *const kSETOMasterKeyScryptBlockSizeKey = @"scryptBlockSize";
NSString *const kSETOMasterKeyPrimaryMasterKeyKey = @"primaryMasterKey";
NSString *const kSETOMasterKeyMacMasterKeyKey = @"hmacMasterKey";

@interface SETOMasterKey ()
@property (nonatomic, assign) uint32_t version;
@property (nonatomic, strong) NSData *versionMac;
@property (nonatomic, strong) NSData *scryptSalt;
@property (nonatomic, assign) uint64_t scryptCostParam;
@property (nonatomic, assign) uint32_t scryptBlockSize;
@property (nonatomic, strong) NSData *primaryMasterKey;
@property (nonatomic, strong) NSData *macMasterKey;
@end

@implementation SETOMasterKey

- (NSDictionary *)dictionaryRepresentation {
	return @{
		kSETOMasterKeyVersionKey: @(self.version),
		kSETOMasterKeyVersionMacKey: [self.versionMac base64EncodedStringWithOptions:0],
		kSETOMasterKeyScryptSaltKey: [self.scryptSalt base64EncodedStringWithOptions:0],
		kSETOMasterKeyScryptCostParamKey: @(self.scryptCostParam),
		kSETOMasterKeyScryptBlockSizeKey: @(self.scryptBlockSize),
		kSETOMasterKeyPrimaryMasterKeyKey: [self.primaryMasterKey base64EncodedStringWithOptions:0],
		kSETOMasterKeyMacMasterKeyKey: [self.macMasterKey base64EncodedStringWithOptions:0]
	};
}

- (BOOL)updateFromJSONData:(NSData *)jsonData {
	NSError *error;
	NSDictionary *jsonDict = [NSJSONSerialization JSONObjectWithData:jsonData options:0 error:&error];
	if (error) {
		return NO;
	} else {
		return [self updateFromDictionary:jsonDict];
	}
}

- (BOOL)updateFromDictionary:(NSDictionary *)dictionary {
	return [KZPropertyMapper mapValuesFrom:dictionary toInstance:self usingMapping:@{
		kSETOMasterKeyVersionKey: KZProperty(version),
		kSETOMasterKeyVersionMacKey: KZCall(dataFromBase64EncodedString:, versionMac),
		kSETOMasterKeyScryptSaltKey: KZCall(dataFromBase64EncodedString:, scryptSalt),
		kSETOMasterKeyScryptCostParamKey: KZProperty(scryptCostParam),
		kSETOMasterKeyScryptBlockSizeKey: KZProperty(scryptBlockSize),
		kSETOMasterKeyPrimaryMasterKeyKey: KZCall(dataFromBase64EncodedString:, primaryMasterKey),
		kSETOMasterKeyMacMasterKeyKey: KZCall(dataFromBase64EncodedString:, macMasterKey)
	}];
}

#pragma mark - Convenience

- (NSData *)dataFromBase64EncodedString:(NSString *)base64EncodedString {
	return [[NSData alloc] initWithBase64EncodedString:base64EncodedString options:0];
}

@end
