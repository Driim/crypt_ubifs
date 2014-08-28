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
 */

/*
 * This file provides a single place to access to encryption and decryption.
 */

#include "ubifs.h"
#include "crypto.h"

#include <linux/err.h>
#include <linux/scatterlist.h>

static struct blkcipher_desc crypto_desc;

static struct ubifs_cipher cipher = {
	.key_flag = 0,
	.name = "aes",
	.capi_name = "xts(aes)",
	.desc = &crypto_desc,
};


static void initializeTweakBytes(uint8_t *tweakBytes, uint64_t tweak) {
	int j;

	for (j=0;j<AES_BLOCK_SIZE;j++) {
		tweakBytes[j] = (uint8_t) (tweak & 0xFF);
		tweak         = tweak >> 8;
	}
}

/**
 * ubifs_crypt - only en/decrypt data
 * @in_buf: data to en/decrypt
 * @in_len: length of the data to en/decrypt
 * @out_buf: output buffer where en/decrypt data should be stored
 * @out_len: output buffer length is returned here
 * @tweak: tweak for aes-xts en/decryption
 * @op: operation encrypt - 1, decrypt - 0
 **/
static int ubifs_crypt(const void *in_buf, int in_len, void *out_buf, int *out_len,
	uint64_t tweak, int op)
{
	struct scatterlist in_sg;
	struct scatterlist out_sg;
	uint8_t tweakBytes[AES_BLOCK_SIZE];
	int ret;

	if(!cipher.key_flag) {
		ubifs_err("Crypto key is not set");
		return EINVAL; /*TODO: error code*/
	}

	sg_init_one(&in_sg, in_buf, in_len);
	sg_init_one(&out_sg, out_buf, *out_len);

	initializeTweakBytes(tweakBytes, tweak);

	cipher.desc->info = tweakBytes;

	if (op)
		ret = crypto_blkcipher_encrypt_iv(cipher.desc, &out_sg, &in_sg, in_len);
	else
		ret = crypto_blkcipher_decrypt_iv(cipher.desc, &out_sg, &in_sg, in_len);

	if(ret) {
		/* TODO: Need more info */
		ubifs_err("Failed to en/decrypt data");
		return EINVAL; /*TODO: error code*/
	}

	return 0;
}

/**
 * ubifs_set_crypto_key - Set en/decryption key
 * @key_buf: key
 * @len: length of key
 *
 * Function set cryptography key.
 **/
int ubifs_set_crypto_key(uint8_t * key_buf, int len)
{
	if(len != AES_KEY_SIZE) {
		/* TODO: in case of error set default cipher to none */
		ubifs_err("Bad key size for %s", cipher.name);
		return EINVAL; /*TODO: error code*/
	}
	if(cipher.key_flag) {
		ubifs_msg("Resetting crypto key");
	}

	if(crypto_blkcipher_setkey(cipher.desc->tfm, key_buf, len)) {
		ubifs_err("cannot set %s key flags=%x",
			cipher.name, crypto_blkcipher_get_flags(cipher.desc->tfm));
		return EINVAL;/*TODO: error code*/
	}

	cipher.key_flag = 1;
	dbg_gen("Cipher %s key was set successfully", cipher.name);
	return 0;
}

int ubifs_encrypt(const void *in_buf, int in_len, void *out_buf, int *out_len,
	uint64_t tweak)
{
	int in_len_aligned;
	void *in_buf_aligned = NULL;
	int ret;

	/*check aligning*/
	in_len_aligned = ALIGN(in_len, AES_BLOCK_SIZE);
	if(in_len_aligned != in_len) {
		in_buf_aligned = kmalloc(in_len_aligned, GFP_NOFS);

		if(!in_buf_aligned) {
			ubifs_err("No memory for cryptobuffer!");
			return -ENOMEM;/*TODO: no memory retval */
		}

		/* Clean buffer not necessarily, just copy data */
		memcpy(in_buf_aligned, in_buf, in_len);
	}
	else {
		in_buf_aligned = (void *)in_buf;
	}

	*out_len = in_len_aligned;

	ret = ubifs_crypt(in_buf_aligned, in_len_aligned,
		out_buf, out_len, tweak, 1);
	if(ret) {
		return ret;
	}

	dbg_gen("encryption of data chunk size=%d, buffer size=%d", in_len, *out_len);

	if(in_buf_aligned != in_buf && in_buf_aligned != NULL) {
		kfree(in_buf_aligned);
	}

	return 0;
}

int ubifs_decrypt(const void *in_buf, int in_len, void *out_buf, int *out_len,
	uint64_t tweak)
{
	int in_len_aligned;
	int ret;

	dbg_gen("decryption of data chunk size=%d, buffer size=%d", in_len, *out_len);

	in_len_aligned = ALIGN(in_len, AES_BLOCK_SIZE);
	if(in_len_aligned != in_len) {
		/* unaligned decryption cannot be done */
		ubifs_err("Cannot decrypt unaligned data");
		return EINVAL;/*TODO: error code*/
	}

	*out_len = in_len;

	ret = ubifs_crypt(in_buf, in_len,
		out_buf, out_len, tweak, 0);
	if(ret) {
		return ret;/*TODO: error code*/
	}

	return 0;
}


/**
 * crypt_init - initialize UBIFS crypto engine
 **/
int __init ubifs_ciphers_init(void)
{
	cipher.desc->tfm = crypto_alloc_blkcipher(cipher.capi_name, 0, 0);
	if (IS_ERR(cipher.desc->tfm)) {
		ubifs_err("cannot initialize cipher %s, error %ld",
			cipher.name, PTR_ERR(cipher.desc->tfm));
		return PTR_ERR(cipher.desc->tfm);
	}

	cipher.desc->flags = 0;
	return 0;
}

/**
 * crypt_exit - de-initialize UBIFS crypto engine
 **/
void ubifs_ciphers_exit(void)
{
	crypto_free_blkcipher(cipher.desc->tfm);
}


inline int ubifs_is_crypted(const struct inode *inode)
{
	const char *name = "user.crypted";
	char buf = 0;
	size_t buf_size = 1;
	ssize_t ret;

	ret = ubifs_getxattr_ino(inode, name, &buf, buf_size);

	if(unlikely(buf)) {
		dbg_gen("crypted inode = %lu", inode->i_ino);
		return 1;
	}

	return 0;
}
