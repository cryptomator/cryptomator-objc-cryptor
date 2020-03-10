//
//  NSData+SETOBase64urlEncoding.h
//  SETOCryptomatorCryptor
//
//  Created by Tobias Hagemann on 11.09.19.
//  Copyright © 2019 Skymatic. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface NSData (SETOBase64urlEncoding)

+ (instancetype)seto_dataWithBase64urlEncodedString:(NSString *)base64urlString;
- (NSString *)seto_base64urlEncodedString;

@end
