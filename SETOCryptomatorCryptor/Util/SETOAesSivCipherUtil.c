//
//  SETOAesSivCipherUtil.c
//  SETOCryptomatorCryptor
//
//  Created by Sebastian Stenzel on 14.02.15.
//  Copyright © 2015-2017 Skymatic. All rights reserved.
//

#include "SETOAesSivCipherUtil.h"
#include "SETOCryptoSupport.h"

#include <assert.h>
#include <string.h>
#include <openssl/cmac.h>
#include <openssl/evp.h>

static const size_t BLOCK_SIZE = 16;

char shift_left(unsigned char *data, size_t len) {
	int carry = 0;
	for (long i = len - 1; i >= 0; i--) {
		short c = data[i] & 0xFF;
		data[i] = 0xFF & (c << 1 | carry);
		carry = 0x01 & (c >> 7);
	}
	return (char)carry;
}

/* ISO7816d4 Padding */
void pad(const unsigned char *input, size_t in_len, unsigned char *out, size_t out_len) {
	for (long i = 0; i < in_len; i++) {
		out[i] = input[i];
	}
	out[in_len] = 0x80;
	for (long i = in_len + 1; i < out_len; i++) {
		out[i] = 0x00;
	}
}

void array_xor(const unsigned char *in1, const unsigned char *in2, unsigned char *out, size_t len) {
	for (int i = 0; i < len; i++) {
		out[i] = in1[i] ^ in2[i];
	}
}

void array_xorend(const unsigned char *in1, size_t in1_len, const unsigned char *in2, size_t in2_len, unsigned char *out) {
	assert(in1_len >= in2_len);
	long diff = in1_len - in2_len;
	for (long i = 0; i < diff; i++) {
		out[i] = in1[i];
	}
	for (long i = diff; i < in1_len; i++) {
		out[i] = in1[i] ^ in2[i - diff];
	}
}

void dbl(unsigned char *data, size_t len) {
	assert(len == 16);
	int carry = shift_left(data, 16);
	data[15] = data[15] ^ (0x87 >> ((1 - carry) << 3));
}

size_t max(size_t a, size_t b) {
	return a > b ? a : b;
}

size_t min(size_t a, size_t b) {
	return a < b ? a : b;
}

int s2v(const unsigned char *mac_key, const size_t mac_key_len, const unsigned char *plaintext, const size_t plaintext_len, const size_t num_additional_data, const unsigned char **additional_data, const size_t *additional_data_sizes, unsigned char *out) {
	assert(mac_key_len == 16 || mac_key_len == 24 || mac_key_len == 32);

	const EVP_CIPHER *cipher;
	switch (mac_key_len) {
		case 16:
			cipher = EVP_aes_128_cbc();
			break;
		case 24:
			cipher = EVP_aes_192_cbc();
			break;
		case 32:
			cipher = EVP_aes_256_cbc();
			break;
		default:
			return -1;
	}

	CMAC_CTX *ctx = CMAC_CTX_new();
	CMAC_Init(ctx, mac_key, mac_key_len, cipher, NULL);

	const unsigned char zeros[BLOCK_SIZE] = {0};
	unsigned char d[BLOCK_SIZE];
	size_t mac_size;

	CMAC_Update(ctx, zeros, BLOCK_SIZE);
	CMAC_Final(ctx, d, &mac_size);

	for (int i = 0; i < num_additional_data; i++) {
		const unsigned char *s = additional_data[i];
		const size_t s_len = additional_data_sizes[i];
		dbl(d, BLOCK_SIZE);
		unsigned char s_mac[BLOCK_SIZE];
		CMAC_Init(ctx, mac_key, mac_key_len, cipher, NULL);
		CMAC_Update(ctx, s, s_len);
		CMAC_Final(ctx, s_mac, &mac_size);
		array_xor(d, s_mac, d, BLOCK_SIZE);
	}

	size_t t_len = max(plaintext_len, BLOCK_SIZE);
	unsigned char t[t_len];
	if (plaintext_len >= BLOCK_SIZE) {
		array_xorend(plaintext, plaintext_len, d, BLOCK_SIZE, t);
	} else {
		dbl(d, BLOCK_SIZE);
		unsigned char padded_plaintext[BLOCK_SIZE];
		pad(plaintext, plaintext_len, padded_plaintext, BLOCK_SIZE);
		array_xor(d, padded_plaintext, t, BLOCK_SIZE);
	}

	CMAC_Init(ctx, mac_key, mac_key_len, cipher, NULL);
	CMAC_Update(ctx, t, t_len);
	CMAC_Final(ctx, out, &mac_size);
	CMAC_CTX_cleanup(ctx);
	CMAC_CTX_free(ctx);
	return 0;
}

int siv_enc(const unsigned char *aes_key, const unsigned char *mac_key, const size_t key_len, const unsigned char *in, const size_t in_len, const size_t num_additional_data, const unsigned char **additional_data, const size_t *additional_data_sizes, unsigned char *out) {
	assert(key_len == 16 || key_len == 24 || key_len == 32);

	const EVP_CIPHER *cipher;
	switch (key_len) {
		case 16:
			cipher = EVP_aes_128_ecb();
			break;
		case 24:
			cipher = EVP_aes_192_ecb();
			break;
		case 32:
			cipher = EVP_aes_256_ecb();
			break;
		default:
			return -1;
	}

	unsigned char iv[16];
	s2v(mac_key, key_len, in, in_len, num_additional_data, additional_data, additional_data_sizes, iv);
	memcpy(out, iv, 16);

	size_t num_blocks = (in_len + BLOCK_SIZE - 1) / BLOCK_SIZE;

	// clear out the 31st and 63rd (rightmost) bit:
	unsigned char ctr[16];
	memcpy(ctr, iv, 16);
	ctr[8] = (ctr[8] & 0x7F);
	ctr[12] = (ctr[12] & 0x7F);
	uint64_t init_ctr_val = big_endian_bytes_to_long(&ctr[8]);

	size_t bytes_encrypted = 0;

	EVP_CIPHER_CTX ctx;
	EVP_CIPHER_CTX_init(&ctx);
	EVP_CIPHER_CTX_set_padding(&ctx, 0);
	EVP_EncryptInit_ex(&ctx, cipher, NULL, aes_key, NULL);
	for (int i = 0; i < num_blocks; i++) {
		uint64_t ctr_val = init_ctr_val + i;
		long_to_big_endian_bytes(ctr_val, &ctr[8]);
		int32_t out_len;
		unsigned char x[16 + BLOCK_SIZE - 1] = {0};
		EVP_EncryptUpdate(&ctx, x, &out_len, ctr, 16);

		const size_t remaining_bytes = in_len - bytes_encrypted;
		array_xor(&in[i * BLOCK_SIZE], x, &out[16 + i * BLOCK_SIZE], min(remaining_bytes, BLOCK_SIZE));
		bytes_encrypted += out_len;
	}
	EVP_CIPHER_CTX_cleanup(&ctx);

	return 0;
}

int siv_dec(const unsigned char *aes_key, const unsigned char *mac_key, const size_t key_len, const unsigned char *in, const size_t in_len, const size_t num_additional_data, const unsigned char **additional_data, const size_t *additional_data_sizes, unsigned char *out) {
	assert(key_len == 16 || key_len == 24 || key_len == 32);

	const EVP_CIPHER *cipher;
	switch (key_len) {
		case 16:
			cipher = EVP_aes_128_ecb();
			break;
		case 24:
			cipher = EVP_aes_192_ecb();
			break;
		case 32:
			cipher = EVP_aes_256_ecb();
			break;
		default:
			return -1;
	}

	unsigned char iv[16];
	memcpy(iv, in, 16);
	const unsigned char *ciphertext = &in[16];
	const size_t ciphertext_len = in_len - 16;

	size_t num_blocks = (ciphertext_len + BLOCK_SIZE - 1) / BLOCK_SIZE;
	assert(num_blocks > 0);

	// clear out the 31st and 63rd (rightmost) bit:
	unsigned char ctr[16];
	memcpy(ctr, iv, 16);
	ctr[8] = (ctr[8] & 0x7F);
	ctr[12] = (ctr[12] & 0x7F);
	uint64_t init_ctr_val = big_endian_bytes_to_long(&ctr[8]);

	size_t bytes_decrypted = 0;

	EVP_CIPHER_CTX ctx;
	EVP_CIPHER_CTX_init(&ctx);
	EVP_CIPHER_CTX_set_padding(&ctx, 0);
	EVP_EncryptInit_ex(&ctx, cipher, NULL, aes_key, NULL);
	for (int i = 0; i < num_blocks; i++) {
		uint64_t ctr_val = init_ctr_val + i;
		long_to_big_endian_bytes(ctr_val, &ctr[8]);
		int32_t out_len;
		unsigned char x[16 + BLOCK_SIZE - 1] = {0};
		EVP_EncryptUpdate(&ctx, x, &out_len, ctr, 16);

		const size_t remaining_bytes = ciphertext_len - bytes_decrypted;
		array_xor(&ciphertext[i * BLOCK_SIZE], x, &out[i * BLOCK_SIZE], min(remaining_bytes, BLOCK_SIZE));
		bytes_decrypted += out_len;
	}
	EVP_CIPHER_CTX_cleanup(&ctx);

	unsigned char control[16];
	s2v(mac_key, key_len, out, ciphertext_len, num_additional_data, additional_data, additional_data_sizes, control);

	int equal = 1;
	for (int i = 0; i < 16; i++) {
		equal &= control[i] == iv[i];
	}
	if (equal) {
		return 0;
	} else {
		return -2;
	}
}
