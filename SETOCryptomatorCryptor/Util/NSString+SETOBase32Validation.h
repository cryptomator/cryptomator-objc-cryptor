//
//  NSString+SETOBase32Validation.h
//  SETOCryptomatorCryptor
//
//  Created by Tobias Hagemann on 10.05.15.
//  Copyright © 2015-2017 Skymatic. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface NSString (SETOBase32Validation)

@property (nonatomic, readonly, getter=seto_isValidBase32Encoded) BOOL seto_validBase32Encoded;

@end
