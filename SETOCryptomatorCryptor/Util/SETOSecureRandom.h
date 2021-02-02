//
//  SETOSecureRandom.h
//  SETOCryptomatorCryptor
//
//  Created by Tobias Hagemann on 01.02.21.
//  Copyright © 2021 Skymatic. All rights reserved.
//

#import <Foundation/Foundation.h>

extern NSString *const kSETOSecureRandomErrorDomain;

typedef NS_ENUM(NSInteger, SETOSecureRandomError) {
	SETOSecureRandomGenerationFailedError
};

@interface SETOSecureRandom : NSObject

+ (instancetype)sharedInstance;
- (NSData *)generateDataWithSize:(NSUInteger)size error:(NSError **)error;

@end
