//
//  SETOCryptorV6.m
//  SETOCryptomatorCryptor
//
//  Created by Tobias Hagemann on 19.06.17.
//  Copyright © 2015-2017 Skymatic. All rights reserved.
//

#import "SETOCryptorV6.h"

@implementation SETOCryptorV6

#pragma mark - Initialization

- (SETOMasterKey *)masterKeyWithPassword:(NSString *)password {
	NSString *normalizedPassword = [password precomposedStringWithCanonicalMapping];
	return [super masterKeyWithPassword:normalizedPassword];
}

@end
