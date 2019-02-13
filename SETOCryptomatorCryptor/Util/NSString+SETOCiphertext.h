//
//  NSString+SETOCiphertext.h
//  SETOCryptomatorCryptor
//
//  Created by Tobias Hagemann on 10.05.15.
//  Copyright © 2015-2017 Skymatic. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface NSString (SETOCiphertext)

@property (nonatomic, readonly, getter=seto_isValidCiphertext) BOOL seto_isValidCiphertext;

@end
