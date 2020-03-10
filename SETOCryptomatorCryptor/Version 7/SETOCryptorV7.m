//
//  SETOCryptorV7.m
//  SETOCryptomatorCryptor
//
//  Created by Tobias Hagemann on 11.09.19.
//  Copyright © 2019 Skymatic. All rights reserved.
//

#import "SETOCryptorV7.h"

#import "NSData+SETOBase64urlEncoding.h"

NSString *const kSETOCryptorV7CiphertextFilenamePattern = @"^([a-zA-Z0-9-_]{4})*[a-zA-Z0-9-_]{20}[a-zA-Z0-9-_=]{4}$";

@implementation SETOCryptorV7

#pragma mark - Path Encoding and Decoding

- (NSString *)encodeFilename:(NSData *)filename {
	return [filename seto_base64urlEncodedString];
}

- (NSData *)decodeFilename:(NSString *)filename {
	return [NSData seto_dataWithBase64urlEncodedString:filename];
}

- (BOOL)isValidEncryptedFilename:(NSString *)filename {
	NSRegularExpression *regex = [NSRegularExpression regularExpressionWithPattern:kSETOCryptorV7CiphertextFilenamePattern options:NSRegularExpressionCaseInsensitive error:NULL];
	NSUInteger numberOfMatches = [regex numberOfMatchesInString:filename options:0 range:NSMakeRange(0, filename.length)];
	return numberOfMatches > 0;
}

@end
