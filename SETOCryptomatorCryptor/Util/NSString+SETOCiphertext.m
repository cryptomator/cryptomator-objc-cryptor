//
//  NSString+SETOCiphertext.m
//  SETOCryptomatorCryptor
//
//  Created by Tobias Hagemann on 10.05.15.
//  Copyright © 2015-2017 Skymatic. All rights reserved.
//

#import "NSString+SETOCiphertext.h"

NSString *const kSETOBase32CiphertextPattern = @"^([A-Z2-7]{8})*[A-Z2-7=]{8}$";

@implementation NSString (SETOCiphertext)

- (BOOL)seto_isValidCiphertext {
	static NSRegularExpression *regex;
	static dispatch_once_t onceToken;
	dispatch_once(&onceToken, ^{
		regex = [NSRegularExpression regularExpressionWithPattern:kSETOBase32CiphertextPattern options:NSRegularExpressionCaseInsensitive error:NULL];
	});
	NSUInteger numberOfMatches = [regex numberOfMatchesInString:self options:0 range:NSMakeRange(0, self.length)];
	return numberOfMatches > 0;
}

@end
