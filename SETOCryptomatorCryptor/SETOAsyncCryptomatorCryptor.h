//
//  SETOAsyncCryptomatorCryptor.h
//  SETOCryptomatorCryptor
//
//  Created by Tobias Hagemann on 18/04/15.
//  Copyright © 2015-2016 setoLabs. All rights reserved.
//

#import "SETOCryptomatorCryptor.h"

/**
 *  `SETOAsyncCryptomatorCryptor` is a `SETOCryptomatorCryptor` decorator for running file content encryption and decryption operations asynchronously.
 */
@interface SETOAsyncCryptomatorCryptor : SETOCryptomatorCryptor

/**
 *  Creates and initializes a `SETOAsyncCryptomatorCryptor` object with the specified master key. The specified dispatch queue will be used for succeeding file content encryption and decryption operations.
 *
 *  @param masterKey The master key for initializing the cryptor.
 *  @param queue The dispatch queue on which succeeding file content encryption and decryption operations will run.
 *
 *  @return The newly-initialized async cryptor.
 */
- (instancetype)initWithMasterKey:(SETOMasterKey *)masterKey queue:(dispatch_queue_t)queue;

@end
