//
//  SETOCryptoSupport.c
//  SETOCryptomatorCryptor
//
//  Created by Sebastian Stenzel on 25/03/15.
//  Copyright © 2015-2016 setoLabs. All rights reserved.
//

#include "SETOCryptoSupport.h"

void int_to_big_endian_bytes(uint32_t num, unsigned char *bytes) {
	bytes[0] = 0xFF & num >> 24;
	bytes[1] = 0xFF & num >> 16;
	bytes[2] = 0xFF & num >> 8;
	bytes[3] = 0xFF & num;
}

uint64_t big_endian_bytes_to_long(const unsigned char *bytes) {
	uint64_t msb = (uint32_t)bytes[0] << 24 | (uint32_t)bytes[1] << 16 | (uint32_t)bytes[2] << 8 | bytes[3];
	uint32_t lsb = (uint32_t)bytes[4] << 24 | (uint32_t)bytes[5] << 16 | (uint32_t)bytes[6] << 8 | bytes[7];
	return msb << 32 | lsb;
}

void long_to_big_endian_bytes(uint64_t lng, unsigned char *bytes) {
	bytes[0] = 0xFF & lng >> 56;
	bytes[1] = 0xFF & lng >> 48;
	bytes[2] = 0xFF & lng >> 40;
	bytes[3] = 0xFF & lng >> 32;
	bytes[4] = 0xFF & lng >> 24;
	bytes[5] = 0xFF & lng >> 16;
	bytes[6] = 0xFF & lng >> 8;
	bytes[7] = 0xFF & lng;
}

void fill_bytes(unsigned char *bytes, unsigned char byte, int offset, int len) {
	for (int i = offset; i < len; i++) {
		bytes[i] = byte;
	}
}

int are_bytes_equal(uint8_t x, uint8_t y) {
	return 1 ^ (((x - y) | (y - x)) >> 7);
}

int compare_bytes(unsigned char *bytes1, unsigned char *bytes2, int len) {
	int equal = 1;
	for (int i = 0; i < len; i++) {
		equal &= are_bytes_equal(bytes1[i], bytes2[i]);
	}
	return equal;
}
