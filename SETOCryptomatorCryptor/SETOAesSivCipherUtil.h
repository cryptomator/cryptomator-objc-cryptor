//
//  SETOAesSivCipherUtil.h
//  SETOCryptomatorCryptor
//
//  Created by Sebastian Stenzel on 14/02/15.
//  Copyright © 2015-2016 setoLabs. All rights reserved.
//

#ifndef __SETOCryptomatorCryptor__SETOAesSivCipherUtil__
#define __SETOCryptomatorCryptor__SETOAesSivCipherUtil__

#include <stdint.h>

/**
 *  s2v
 *
 *  @param mac_key               mac key
 *  @param mac_key_len           mac key lenth
 *  @param plaintext             plaintext
 *  @param plaintext_len         plantext length
 *  @param num_additional_data   number of additional data
 *  @param additional_data       additional data (two-dimensional)
 *  @param additional_data_sizes additional data sizes
 *  @param out                   buffer with at least 16 bytes
 *
 *  @return 0 on success
 */
int s2v(const unsigned char *mac_key, const size_t mac_key_len, const unsigned char *plaintext, const size_t plaintext_len, const size_t num_additional_data, const unsigned char **additional_data, const size_t *additional_data_sizes, unsigned char *out);

/**
 *  siv_enc
 *
 *  @param aes_key               aes key
 *  @param mac_key               mac key
 *  @param key_len               aes/mac key length
 *  @param in                    plaintext
 *  @param in_len                plaintext length
 *  @param num_additional_data   number of additional data
 *  @param additional_data       additional data (two-dimensional)
 *  @param additional_data_sizes additional data sizes
 *  @param out                   buffer with at least in_len + 16 bytes
 *
 *  @return 0 on success
 */
int siv_enc(const unsigned char *aes_key, const unsigned char *mac_key, const size_t key_len, const unsigned char *in, const size_t in_len, const size_t num_additional_data, const unsigned char **additional_data, const size_t *additional_data_sizes, unsigned char *out);

/**
 *  siv_dec
 *
 *  @param aes_key               aes key
 *  @param mac_key               mac key
 *  @param key_len               aes/mac key length
 *  @param in                    ciphertext
 *  @param in_len                ciphertext length
 *  @param num_additional_data   number of additional data
 *  @param additional_data       additional data (two-dimensional)
 *  @param additional_data_sizes additional data sizes
 *  @param out                   buffer with at least in_len - 16 bytes
 *
 *  @return 0 on success
 */
int siv_dec(const unsigned char *aes_key, const unsigned char *mac_key, const size_t key_len, const unsigned char *in, const size_t in_len, const size_t num_additional_data, const unsigned char **additional_data, const size_t *additional_data_sizes, unsigned char *out);

#endif /* defined(__SETOCryptomatorCryptor__SETOAesSivCipherUtil__) */
