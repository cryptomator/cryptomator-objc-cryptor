//
//  NSString+SETOBase32Validation.m
//  SETOCryptomatorCryptor
//
//  Created by Tobias Hagemann on 10/05/15.
//  Copyright © 2015-2016 setoLabs. All rights reserved.
//

#import "NSString+SETOBase32Validation.h"

NSString *const kSETOBase32Pattern = @"^[a-z2-7]+=*$";

@implementation NSString (SETOBase32Validation)

- (BOOL)seto_isValidBase32Encoded {
	static NSRegularExpression *regex;
	static dispatch_once_t onceToken;
	dispatch_once(&onceToken, ^{
		regex = [NSRegularExpression regularExpressionWithPattern:kSETOBase32Pattern options:NSRegularExpressionCaseInsensitive error:NULL];
	});
	NSUInteger numberOfBase32Matches = [regex numberOfMatchesInString:self options:0 range:NSMakeRange(0, self.length)];
	return numberOfBase32Matches > 0;
}

@end
