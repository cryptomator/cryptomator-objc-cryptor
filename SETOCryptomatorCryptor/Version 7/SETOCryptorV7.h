//
//  SETOCryptorV7.h
//  SETOCryptomatorCryptor
//
//  Created by Tobias Hagemann on 11.09.19.
//  Copyright © 2019 Skymatic. All rights reserved.
//

#import "SETOCryptorV6.h"

/**
 *  Beginning with vault format v7, filenames are encoded with base64url so that name shortenings are less likely. The ciphertext file layout has been redesigned.
 *
 *  This is an example of the new vault structure:
 *  @code
 *  .
 *  ├─ d
 *  │  ├─ BZ
 *  │  │  └─ R4VZSS5PEF7TU3PMFIMON5GJRNBDWA
 *  │  │     ├─ 5TyvCyF255sRtfrIv__83ucADQ==.c9r  # regular file
 *  │  │     ├─ FHTa55bH_sUfVDbEb0gTL9hZ8nho.c9r  # irregular file...
 *  │  │     │  └─ dir.c9r  # ...which is a directory
 *  │  │     ├─ gLeOGMCN358_UBf2Qk9cWCQl.c9r  # irregular file...
 *  │  │     │  └─ symlink.c9r  # ...which is a symlink
 *  │  │     ├─ IjTsXtReTy6bAAuxzLPV9T0k2vg=.c9s  # shortened name...
 *  │  │     │  ├─ contents.c9r  # ...which is a regular file
 *  │  │     │  └─ name.c9s  # ...mapping to this full name
 *  │  │     ├─ q2nx5XeNCenHyQvkFD4mxYNrWpQ=.c9s  # shortened name...
 *  │  │     │  ├─ dir.c9r  # ...which is a directory
 *  │  │     │  └─ name.c9s  # ...mapping to this full name
 *  │  │     ├─ u_JJCJE-T4IH-EBYASUp1u3p7mA=.c9s  # shortened name...
 *  │  │     │  ├─ name.c9s  # ...mapping to this full name
 *  │  │     │  └─ symlink.c9r  # ...which is a symlink
 *  │  │     └─ ...
 *  │  └─ FC
 *  │     └─ ZKZRLZUODUUYTYA4457CSBPZXB5A77
 *  │        └─ ...
 *  ├─ masterkey.cryptomator
 *  └─ masterkey.cryptomator.DFD9B248.bkup
 *  @endcode
 */
@interface SETOCryptorV7 : SETOCryptorV6

@end
