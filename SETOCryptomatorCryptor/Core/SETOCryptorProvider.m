//
//  SETOCryptorProvider.m
//  SETOCryptomatorCryptor
//
//  Created by Tobias Hagemann on 03.02.21.
//  Copyright © 2021 Skymatic. All rights reserved.
//

#import "SETOCryptorProvider.h"
#import "SETOCryptorV3.h"
#import "SETOCryptorV5.h"
#import "SETOCryptorV7.h"
#import "SETOMasterKey.h"

NSString *const kSETOCryptorProviderErrorDomain = @"SETOCryptorProviderErrorDomain";

@implementation SETOCryptorProvider

+ (SETOCryptor *)cryptorWithMasterKey:(SETOMasterKey *)masterKey forVaultVersion:(NSInteger)vaultVersion error:(NSError **)error {
	if (vaultVersion >= 3 && vaultVersion <= 4) {
		return [[SETOCryptorV3 alloc] initWithMasterKey:masterKey];
	} else if (vaultVersion >= 5 && vaultVersion <= 6) {
		return [[SETOCryptorV5 alloc] initWithMasterKey:masterKey];
	} else if (vaultVersion >= 7 && vaultVersion <= 8) {
		return [[SETOCryptorV7 alloc] initWithMasterKey:masterKey];
	} else {
		if (error) {
			*error = [NSError errorWithDomain:kSETOCryptorProviderErrorDomain code:SETOCryptorProviderUnsupportedVaultFormatError userInfo:nil];
		}
		return nil;
	}
}

@end
