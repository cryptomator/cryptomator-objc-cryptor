//
//  NSData+SETOBase64urlEncoding.m
//  SETOCryptomatorCryptor
//
//  Created by Tobias Hagemann on 11.09.19.
//  Copyright © 2019 Skymatic. All rights reserved.
//

#import "NSData+SETOBase64urlEncoding.h"

@implementation NSData (SETOBase64urlEncoding)

+ (instancetype)seto_dataWithBase64urlEncodedString:(NSString *)base64urlString {
	NSString *base64String = [base64urlString stringByReplacingOccurrencesOfString:@"-" withString:@"+"];
	base64String = [base64String stringByReplacingOccurrencesOfString:@"_" withString:@"/"];
	return [[NSData alloc] initWithBase64EncodedString:base64String options:0];
}

- (NSString *)seto_base64urlEncodedString:(NSData *)data {
	if (!data.bytes) {
		return [NSString string];
	}
	NSString *base64urlString = [data base64EncodedStringWithOptions:0];
	base64urlString = [base64urlString stringByReplacingOccurrencesOfString:@"+" withString:@"-"];
	base64urlString = [base64urlString stringByReplacingOccurrencesOfString:@"/" withString:@"_"];
	return base64urlString;
}

@end
