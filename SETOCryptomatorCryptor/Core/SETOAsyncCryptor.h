//
//  SETOAsyncCryptor.h
//  SETOCryptomatorCryptor
//
//  Created by Tobias Hagemann on 18.04.15.
//  Copyright © 2015-2017 Skymatic. All rights reserved.
//

#import "SETOCryptor.h"

/**
 *  @c SETOAsyncCryptor is a @c SETOCryptor decorator for running file content encryption and decryption operations asynchronously.
 */
@interface SETOAsyncCryptor : SETOCryptor

/**
 *  Creates and initializes a @c SETOAsyncCryptor object decorating the specified cryptor. The specified dispatch queue will be used for succeeding file content encryption and decryption operations.
 *
 *  @param cryptor The cryptor to decorate.
 *  @param queue The dispatch queue on which succeeding file content encryption and decryption operations will run.
 *
 *  @return The newly-initialized async cryptor.
 */
- (instancetype)initWithCryptor:(SETOCryptor *)cryptor queue:(dispatch_queue_t)queue NS_DESIGNATED_INITIALIZER;

/**
 *  Creates and initializes a @c SETOAsyncCryptor object decorating the specified cryptor. A serial queue (utility QoS class) will be created and used for succeeding file content encryption and decryption operations.
 *
 *  @param cryptor The cryptor to decorate.
 *
 *  @return The newly-initialized async cryptor.
 */
- (instancetype)initWithCryptor:(SETOCryptor *)cryptor;

/**
 *  Unavailable initialization method, use -initWithCryptor:queue: instead.
 *
 *  @see -initWithCryptor:queue:
 */
- (instancetype)initWithPrimaryMasterKey:(NSData *)primaryMasterKey macMasterKey:(NSData *)macMasterKey version:(SETOCryptorVersion)version NS_UNAVAILABLE;

@end
