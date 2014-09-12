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

static DEFINE_MUTEX(cipher_mutex);

static struct blkcipher_desc crypto_desc;

static struct ubifs_cipher cipher = {
	.key_flag = 0,
	.name = "aes",
	.init_flag = 0,
	.capi_name = "xts(aes)",
	.desc = &crypto_desc,
	.ciph_mutex = &cipher_mutex,
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
 *
 * Note: in_buf must be aligned to cipher block
 **/
static int ubifs_crypt(const void *in_buf, int in_len, void *out_buf, int *out_len,
	uint64_t tweak, int op)
{
	struct scatterlist sg[2];

	uint8_t tweakBytes[AES_BLOCK_SIZE];
	int ret;

	if(!cipher.key_flag) {
		ubifs_err("Crypto key is not set");
		return EINVAL; /*TODO: error code*/
	}

	sg_init_one(&sg[0], in_buf, in_len);
	sg_init_one(&sg[1], out_buf, *out_len);

	initializeTweakBytes(tweakBytes, tweak);

	crypto_blkcipher_set_iv(cipher.desc->tfm, tweakBytes, AES_BLOCK_SIZE);

	if (op)
		ret = crypto_blkcipher_encrypt(cipher.desc, &sg[1], &sg[0], in_len);
	else
		ret = crypto_blkcipher_decrypt(cipher.desc, &sg[1], &sg[0], in_len);

	if(ret) {
		/* TODO: Need more info */
		ubifs_err("Failed to en/decrypt data");
		return -EINVAL; /*TODO: error code*/
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
	if(!cipher.init_flag)
		return -EINVAL;

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
		return -EINVAL;/*TODO: error code*/
	}

	cipher.key_flag = 1;
	dbg_gen("Cipher %s key was set successfully", cipher.name);
	return 0;
}

/**
 * ubifs_encrypt - Encrypt data
 * @in_buf: input buffer
 * @in_len: length of input buffer
 * @out_buf: output buffer
 * @out_len: store size of data after encryption
 * @tweak: tweak value
 *
 **/
int ubifs_encrypt(const void *in_buf, int in_len, void *out_buf, int *out_len,
	uint64_t tweak)
{
	int in_len_aligned;
	void *in_buf_aligned = NULL;
	int ret;

	if(!cipher.init_flag)
		return -EINVAL;

	/*
	 *	FIXME:cryptoapi(scatterlist) works with error if we use in_buf
	 *        that come from ubifs_writepage, so buffer for encryption
	 *        we create here and do aligning if need it
	 */
	in_len_aligned = ALIGN(in_len, AES_BLOCK_SIZE);
	in_buf_aligned = kmalloc(in_len_aligned, GFP_NOFS);
	if(!in_buf_aligned) {
		ubifs_err("No memory");
		return -ENOMEM;
	}
	memcpy(in_buf_aligned, in_buf, in_len);

	*out_len = in_len_aligned;

	mutex_lock(cipher.ciph_mutex);

	ret = ubifs_crypt(in_buf_aligned, in_len_aligned,
									out_buf, out_len, tweak, 1);
	mutex_unlock(cipher.ciph_mutex); /* TODO: mutex may be not need here */
	if(ret) {
		ubifs_err("encryption error");
		return ret;
	}

	mutex_unlock(cipher.ciph_mutex);
	kfree(in_buf_aligned);

	return 0;
}

/**
 * ubifs_decrypt - Encrypt data
 * @in_buf: input buffer
 * @in_len: length of input buffer
 * @out_buf: output buffer
 * @data_len: store size of data after encryption
 * @tweak: tweak value
 *
 **/
int ubifs_decrypt(const void *in_buf, int in_len, void *out_buf, int data_len,
	uint64_t tweak)
{
	int in_len_aligned, tmp_len;
	int ret;
	void * out_buf_tmp = NULL;

	if(!cipher.init_flag)
		return -EINVAL;

	in_len_aligned = ALIGN(in_len, AES_BLOCK_SIZE);
	if(in_len_aligned != in_len) {
		/* unaligned decryption cannot be done */
		ubifs_err("Cannot decrypt unaligned data");
		return -EINVAL;
	}

	/*
	 *	FIXME: cryptoapi(scatterlist) works with error if we use in_buf
	 *         that come from ubifs_writepage, so buffer for encryption
	 *         we create here and do aligning if need it
	 */
	out_buf_tmp = kmalloc(in_len, GFP_NOFS);
	if(!out_buf_tmp) {
		ubifs_err("No memory");
		return -ENOMEM;
	}

	mutex_lock(cipher.ciph_mutex);

	ret = ubifs_crypt(in_buf, in_len, out_buf_tmp, &tmp_len, tweak, 0);
	if(ret) {
		ubifs_err("decryption error");
		mutex_unlock(cipher.ciph_mutex);
		return ret;
	}

	mutex_unlock(cipher.ciph_mutex);

	memcpy(out_buf, out_buf_tmp, data_len); /*the real(unaligned) size stored in data_len*/
	kfree(out_buf_tmp);

	return 0;
}


/**
 * crypt_init - initialize UBIFS crypto engine
 **/
int __init ubifs_ciphers_init(void)
{
	cipher.desc->tfm = crypto_alloc_blkcipher(cipher.capi_name, 0, 0);
	if (IS_ERR(cipher.desc->tfm)) {
		/* UBIFS can normally work without cipher */
		return 0;
	}

	cipher.init_flag = 1;
	cipher.desc->flags = 0;
	return 0;
}

/**
 * crypt_exit - de-initialize UBIFS crypto engine
 **/
void ubifs_ciphers_exit(void)
{
	if(cipher.init_flag)
		crypto_free_blkcipher(cipher.desc->tfm);
}


inline int ubifs_is_crypted(const struct inode *inode)
{
	return ubifs_inode(inode)->crypted;
}

int ubifs_is_inode_crypted(const struct inode *inode)
{
	const char *name = "user.crypted";
	struct ubifs_inode *ui = ubifs_inode(inode);
	char buf = 0;
	size_t buf_size = 1;
	ssize_t ret;

	if(!cipher.init_flag || ui->xattr_cnt == 0)
		return 0;

	ret = ubifs_getxattr_ino(inode, name, &buf, buf_size);

	if(buf) {
		dbg_gen("crypted inode = %lu", inode->i_ino);
		return 1;
	}

	return 0;
}
