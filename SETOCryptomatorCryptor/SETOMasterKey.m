//
//  SETOMasterKey.m
//  SETOCryptomatorCryptor
//
//  Created by Tobias Hagemann on 21/02/15.
//  Copyright © 2015-2016 setoLabs. All rights reserved.
//

#import "SETOMasterKey.h"

#import <KZPropertyMapper/KZPropertyMapper.h>

NSString *const kSETOMasterKeyFileMimeType = @"application/json";
NSUInteger const kSETOMasterKeyCurrentVersion = 3;

NSString *const kSETOMasterKeyVersionKey = @"version";
NSString *const kSETOMasterKeyScryptSaltKey = @"scryptSalt";
NSString *const kSETOMasterKeyScryptCostParamKey = @"scryptCostParam";
NSString *const kSETOMasterKeyScryptBlockSizeKey = @"scryptBlockSize";
NSString *const kSETOMasterKeyPrimaryMasterKeyKey = @"primaryMasterKey";
NSString *const kSETOMasterKeyMacMasterKeyKey = @"hmacMasterKey";

@interface SETOMasterKey ()
@property (nonatomic, assign) NSUInteger version;
@property (nonatomic, strong) NSData *scryptSalt;
@property (nonatomic, assign) NSUInteger scryptCostParam;
@property (nonatomic, assign) NSUInteger scryptBlockSize;
@property (nonatomic, strong) NSData *primaryMasterKey;
@property (nonatomic, strong) NSData *macMasterKey;
@end

@implementation SETOMasterKey

- (BOOL)updateFromJsonData:(NSData *)jsonData {
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
		kSETOMasterKeyScryptSaltKey: KZCall(dataFromBase64EncodedString:, scryptSalt),
		kSETOMasterKeyScryptCostParamKey: KZProperty(scryptCostParam),
		kSETOMasterKeyScryptBlockSizeKey: KZProperty(scryptBlockSize),
		kSETOMasterKeyPrimaryMasterKeyKey: KZCall(dataFromBase64EncodedString:, primaryMasterKey),
		kSETOMasterKeyMacMasterKeyKey: KZCall(dataFromBase64EncodedString:, macMasterKey),
	}];
}

- (NSData *)dataFromBase64EncodedString:(NSString *)base64EncodedString {
	return [[NSData alloc] initWithBase64EncodedString:base64EncodedString options:0];
}

- (NSDictionary *)dictionaryRepresentation {
	return @{
		kSETOMasterKeyVersionKey: @(self.version),
		kSETOMasterKeyScryptSaltKey: [self.scryptSalt base64EncodedStringWithOptions:0],
		kSETOMasterKeyScryptCostParamKey: @(self.scryptCostParam),
		kSETOMasterKeyScryptBlockSizeKey: @(self.scryptBlockSize),
		kSETOMasterKeyPrimaryMasterKeyKey: [self.primaryMasterKey base64EncodedStringWithOptions:0],
		kSETOMasterKeyMacMasterKeyKey: [self.macMasterKey base64EncodedStringWithOptions:0]
	};
}

@end
