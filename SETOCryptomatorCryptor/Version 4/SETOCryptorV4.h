//
//  SETOCryptorV4.h
//  SETOCryptomatorCryptor
//
//  Created by Tobias Hagemann on 19.06.17.
//  Copyright © 2015-2017 Skymatic. All rights reserved.
//

#import "SETOCryptorV3.h"

/**
 *  Beginning with vault format v4, directories have a different trait.
 *
 *  Directories now have 0 (zero) prefix instead of a _ (underscore) suffix. No implementation needed because this change isn't part of this library.
 */
@interface SETOCryptorV4 : SETOCryptorV3

@end
