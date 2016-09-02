//
//  SETOCryptoSupport.h
//  SETOCryptomatorCryptor
//
//  Created by Sebastian Stenzel on 25/03/15.
//  Copyright © 2015-2016 setoLabs. All rights reserved.
//

#ifndef __SETOCryptomatorCryptor__SETOCryptoSupport__
#define __SETOCryptomatorCryptor__SETOCryptoSupport__

#include <stdio.h>

void int_to_big_endian_bytes(uint32_t num, unsigned char *bytes);
uint64_t big_endian_bytes_to_long(const unsigned char *bytes);
void long_to_big_endian_bytes(uint64_t lng, unsigned char *bytes);
void fill_bytes(unsigned char *bytes, unsigned char byte, int offset, int len);
int compare_bytes(unsigned char *bytes1, unsigned char *bytes2, int len);

#endif /* defined(__SETOCryptomatorCryptor__SETOCryptoSupport__) */
