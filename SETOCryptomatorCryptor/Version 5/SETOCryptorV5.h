//
//  SETOCryptorV5.h
//  SETOCryptomatorCryptor
//
//  Created by Tobias Hagemann on 02.09.16.
//  Copyright © 2015-2017 Skymatic. All rights reserved.
//

#import "SETOCryptorV4.h"

/**
 *  Beginning with vault format v5, file size obfuscation has been disabled.
 *
 *  File sizes can be determined in O(1) instead of having to read and decrypt the file header. This allows showing file sizes in the directory listing without having to download each file first. The file size in the header is now unused and filled with 0xFFFFFFFFFFFFFFFF.
 */
@interface SETOCryptorV5 : SETOCryptorV4

@end
