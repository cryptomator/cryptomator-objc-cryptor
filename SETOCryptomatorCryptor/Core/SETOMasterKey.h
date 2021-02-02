//
//  SETOMasterKey.h
//  SETOCryptomatorCryptor
//
//  Created by Tobias Hagemann on 21.02.15.
//  Copyright © 2015-2017 Skymatic. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface SETOMasterKey : NSObject

@property (nonatomic, readonly) NSData *aesMasterKey;
@property (nonatomic, readonly) NSData *macMasterKey;

/**
 *  Creates masterkey from raw bytes.
 *
 *  @param aesMasterKey Key used for encryption of file specific keys.
 *  @param macMasterKey Key used for file authentication.
 *
 *  @return New masterkey instance using the keys from the supplied raw bytes.
 */
- (instancetype)initWithAESMasterKey:(NSData *)aesMasterKey macMasterkey:(NSData *)macMasterKey;

/**
 *  Creates new masterkey.
 *
 *  @return New masterkey instance with secure random bytes.
 */
- (instancetype)init;

@end
