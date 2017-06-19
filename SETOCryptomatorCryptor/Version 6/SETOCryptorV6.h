//
//  SETOCryptorV6.h
//  SETOCryptomatorCryptor
//
//  Created by Tobias Hagemann on 19.06.17.
//  Copyright © 2015-2017 Skymatic. All rights reserved.
//

#import "SETOCryptorV5.h"

/**
 *  Beginning with vault format v6, the password is normalized in NFC.
 */
@interface SETOCryptorV6 : SETOCryptorV5

@end
