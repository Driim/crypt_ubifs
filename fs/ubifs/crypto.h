/*
 * This file is part of UBIFS.
 *
 * Copyright (C) 2014 digiFLAK
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published by
 * the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 *
 * Author: Dmitry Falko
 *
 */

#ifndef __UBIFS_CRYPTO_H__
#define __UBIFS_CRYPTO_H__

#include <linux/crypto.h>

#define AES_BLOCK_SIZE 16
#define AES_KEY_SIZE   32

#define XATTR_CRYPT_FLAG ("user.crypted")

/**
 * struct ubifs_cipher - UBIFS cipher description structure.
 * @cipher_type: cipher type (%UBIFS_CIPHER_AES_XTS, etc)
 * @key_flag: crypto key flag
 * @desc: cryptoapi descriptor handle
 * @name: cipher name
 * @capi_name: cryptoapi cipher name
 */
struct ubifs_cipher {
	int cipher_type;
	int key_flag;
	int init_flag;
	struct blkcipher_desc *desc;
	struct mutex *ciph_mutex;
	const char *name;
	const char *capi_name;
};

int ubifs_ciphers_init(void);
void ubifs_ciphers_exit(void);
int ubifs_set_crypto_key(uint8_t * key_buf, int len);
int ubifs_encrypt(const void *in_buf, int in_len, void *out_buf, int *out_len,
	uint64_t tweak);
int ubifs_decrypt(const void *in_buf, int in_len, void *out_buf, int data_len,
	uint64_t tweak);
inline int ubifs_is_crypted(const struct inode *inode);
int ubifs_is_inode_crypted(const struct inode *inode);

#endif /* !__UBIFS_CRYPTO_H__ */
