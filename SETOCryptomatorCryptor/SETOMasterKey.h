//
//  SETOMasterKey.h
//  SETOCryptomatorCryptor
//
//  Created by Tobias Hagemann on 21/02/15.
//  Copyright © 2015-2016 setoLabs. All rights reserved.
//

#import <Foundation/Foundation.h>

extern NSString *const kSETOMasterKeyFileMimeType;
extern NSUInteger const kSETOMasterKeyCurrentVersion;

extern NSString *const kSETOMasterKeyVersionKey;
extern NSString *const kSETOMasterKeyScryptSaltKey;
extern NSString *const kSETOMasterKeyScryptCostParamKey;
extern NSString *const kSETOMasterKeyScryptBlockSizeKey;
extern NSString *const kSETOMasterKeyPrimaryMasterKeyKey;
extern NSString *const kSETOMasterKeyMacMasterKeyKey;

@interface SETOMasterKey : NSObject

@property (nonatomic, readonly) NSUInteger version;
@property (nonatomic, readonly) NSData *scryptSalt;
@property (nonatomic, readonly) NSUInteger scryptCostParam;
@property (nonatomic, readonly) NSUInteger scryptBlockSize;
@property (nonatomic, readonly) NSData *primaryMasterKey;
@property (nonatomic, readonly) NSData *macMasterKey;

@property (nonatomic, readonly, getter=dictionaryRepresentation) NSDictionary *dictionaryRepresentation;

- (BOOL)updateFromJsonData:(NSData *)jsonData;
- (BOOL)updateFromDictionary:(NSDictionary *)dictionary;

@end
