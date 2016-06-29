//
//  SETOMasterKey.h
//  SETOCryptomatorCryptor
//
//  Created by Tobias Hagemann on 21/02/15.
//  Copyright © 2015-2016 setoLabs. All rights reserved.
//

#import <Foundation/Foundation.h>

@class SETOCryptor;

extern NSString *const kSETOMasterKeyVersionKey;
extern NSString *const kSETOMasterKeyVersionMacKey;
extern NSString *const kSETOMasterKeyScryptSaltKey;
extern NSString *const kSETOMasterKeyScryptCostParamKey;
extern NSString *const kSETOMasterKeyScryptBlockSizeKey;
extern NSString *const kSETOMasterKeyPrimaryMasterKeyKey;
extern NSString *const kSETOMasterKeyMacMasterKeyKey;

/**
 *  @c SETOMasterKey holds the information necessary for the master key.
 */
@interface SETOMasterKey : NSObject

@property (nonatomic, readonly) uint32_t version;
@property (nonatomic, readonly) NSData *versionMac;
@property (nonatomic, readonly) NSData *scryptSalt;
@property (nonatomic, readonly) uint64_t scryptCostParam;
@property (nonatomic, readonly) uint32_t scryptBlockSize;
@property (nonatomic, readonly) NSData *primaryMasterKey;
@property (nonatomic, readonly) NSData *macMasterKey;

/**
 *  Creates a dictionary representation of this master key.
 */
@property (nonatomic, readonly, getter=dictionaryRepresentation) NSDictionary *dictionaryRepresentation;

/**
 *  Updates master key from specified JSON data.
 *
 *  @param jsonData The master key data in JSON format.
 *
 *  @return @c YES, if the master key has been successfully updated, otherwise @c NO.
 */
- (BOOL)updateFromJSONData:(NSData *)jsonData;

/**
 *  Updates master key from specified dictionary.
 *
 *  @param dictionary The master key data as dictionary.
 *
 *  @return @c YES, if the master key has been successfully updated, otherwise @c NO.
 */
- (BOOL)updateFromDictionary:(NSDictionary *)dictionary;

@end
