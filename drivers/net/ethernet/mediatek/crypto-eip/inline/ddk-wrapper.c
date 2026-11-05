// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2023 MediaTek Inc.
 *
 * Author: Chris.Chou <chris.chou@mediatek.com>
 *         Ren-Ting Wang <ren-ting.wang@mediatek.com>
 *
 * Glue between the xfrm offload code and the Rambus DDK (inline IPsec part).
 */

#include <crypto/aes.h>
#include <crypto/ctr.h>
#include <crypto/hash.h>
#include <crypto/md5.h>
#include <crypto/skcipher.h>
#include <linux/delay.h>
#include <linux/scatterlist.h>

#include <crypto-eip/ddk/slad/api_pcl.h>
#include <crypto-eip/ddk/slad/api_pcl_dtl.h>
#include <crypto-eip/ddk/slad/api_pec.h>

#include "crypto-eip/crypto-eip.h"
#include "crypto-eip/ddk-wrapper.h"
#include "crypto-eip/internal.h"

void crypto_free_sa(void *sa_pointer, int ring)
{
	DMABuf_Handle_t SAHandle = {0};

	if (ring < 0)
		return;

	SAHandle.p = sa_pointer;
	PEC_SA_UnRegister(ring, SAHandle, DMABuf_NULLHandle,
				DMABuf_NULLHandle);
	DMABuf_Release(SAHandle);
}

static bool crypto_iotoken_create(IOToken_Input_Dscr_t * const dscr_p,
				  void * const ext_p, u32 *data_p,
				  PEC_CommandDescriptor_t * const pec_cmd_dscr)
{
	int IOTokenRc;

	dscr_p->InPacket_ByteCount = pec_cmd_dscr->SrcPkt_ByteCount;
	dscr_p->Ext_p = ext_p;

	IOTokenRc = IOToken_Create(dscr_p, data_p);
	if (IOTokenRc < 0) {
		CRYPTO_ERR("IOToken_Create error %d\n", IOTokenRc);
		return false;
	}

	pec_cmd_dscr->InputToken_p = data_p;

	return true;
}

static unsigned int crypto_pe_busy_get_one(IOToken_Output_Dscr_t *const OutTokenDscr_p,
			       u32 *OutTokenData_p,
			       PEC_ResultDescriptor_t *RD_p, int ring)
{
	int LoopCounter = MTK_EIP197_INLINE_NOF_TRIES;
	int IOToken_Rc;
	PEC_Status_t pecres;

	ZEROINIT(*OutTokenDscr_p);
	ZEROINIT(*RD_p);

	/* Link data structures */
	RD_p->OutputToken_p = OutTokenData_p;

	while (LoopCounter > 0) {
		/* Try to get the processed packet from the driver */
		unsigned int Counter = 0;

		pecres = PEC_Packet_Get(ring, RD_p, 1, &Counter);
		if (pecres != PEC_STATUS_OK) {
			if (pecres == PEC_STATUS_BUSY)
				goto wait;
			/* IO error */
			CRYPTO_ERR("PEC_Packet_Get error %d\n", pecres);
			return 0;
		}

		if (Counter) {
			IOToken_Rc = IOToken_Parse(OutTokenData_p, OutTokenDscr_p);
			if (IOToken_Rc < 0) {
				/* IO error */
				CRYPTO_ERR("IOToken_Parse error %d\n", IOToken_Rc);
				return 0;
			}

			if (OutTokenDscr_p->ErrorCode != 0) {
				/* Packet process error */
				CRYPTO_ERR("Result descriptor error 0x%x\n",
					OutTokenDscr_p->ErrorCode);
				return 0;
			}

			/* packet received */
			return Counter;
		}

wait:
		/* Wait for MTK_EIP197_PKT_GET_TIMEOUT_MS milliseconds */
		udelay(MTK_EIP197_PKT_GET_TIMEOUT_MS * 1000);
		LoopCounter--;
	}

	/* IO error (timeout, not result packet received) */
	return 0;
}

static bool crypto_basic_hash(struct ahash_request *areq, uint8_t *input,
				unsigned int input_length, uint8_t *output, bool final)
{
	DECLARE_CRYPTO_WAIT(wait);
	struct scatterlist sg;
	int ret;

	ahash_request_set_callback(areq, CRYPTO_TFM_REQ_MAY_BACKLOG, crypto_req_done, &wait);
	sg_init_one(&sg, input, input_length);
	ahash_request_set_crypt(areq, &sg, output, input_length);

	if (final) {
		ret = crypto_ahash_digest(areq);
		if (ret && ret != -EINPROGRESS && ret != -EBUSY) {
			pr_notice("%s: hash update failed: %d\n", __func__, ret);
			return false;
		}
		ret = crypto_wait_req(ret, &wait);
		if (ret) {
			pr_notice("%s: hash failed: %d\n", __func__, ret);
			return false;
		}
	} else {
		ret = crypto_ahash_init(areq);
		if (ret) {
			pr_notice("%s: hash init failed: %d\n", __func__, ret);
			return false;
		}

		ret = crypto_ahash_update(areq);
		if (ret && ret != -EINPROGRESS && ret != -EBUSY) {
			pr_notice("%s: hash update failed: %d\n", __func__, ret);
			return false;
		}

		ret = crypto_wait_req(ret, &wait);
		if (ret) {
			pr_notice("%s: hash failed: %d\n", __func__, ret);
			return false;
		}

		ret = crypto_ahash_export(areq, output);
		if (ret) {
			pr_notice("%s: hash export failed: %d\n", __func__, ret);
			return false;
		}
	}

	return true;
}

static void mtk_crypto_hash_byteswap(SABuilder_Auth_t algo, uint8_t *input, unsigned int length)
{
	int i;
	u32 temp;

	if (algo == SAB_AUTH_HMAC_MD5)
		return;

	/* Byte swapping for 32-bit word hash (ex. sha1, sha256) */
	for (i = 0; i < (length / 4); i++)
		((__be32 *)input)[i] = cpu_to_be32(((__le32 *)input)[i]);

	/* Extra swap for 64-bit word hash (ex. sha384, sha512) */
	if (algo == SAB_AUTH_HMAC_SHA2_384 || algo == SAB_AUTH_HMAC_SHA2_512) {
		for (i = 0; i < (length / 4); i = i + 2) {
			temp = ((u32 *)input)[i];
			((u32 *)input)[i] = ((u32 *)input)[i + 1];
			((u32 *)input)[i + 1] = temp;
		}
	}
}

bool crypto_hmac_precompute(SABuilder_Auth_t AuthAlgo,
			    uint8_t *AuthKey_p,
			    unsigned int AuthKeyByteCount,
			    uint8_t *Inner_p,
			    uint8_t *Outer_p)
{
	unsigned int blocksize, digestsize;
	uint8_t pad_block[128], hashed_key[128];
	unsigned int i;
	struct ahash_request *areq = NULL;
	struct crypto_ahash *atfm = NULL;
	bool ret = false;
	uint8_t *state = NULL;

	switch (AuthAlgo) {
	case SAB_AUTH_HMAC_MD5:
		atfm = crypto_alloc_ahash("md5", 0, 0);
		digestsize = 16;
		break;
	case SAB_AUTH_HMAC_SHA1:
		atfm = crypto_alloc_ahash("sha1", 0, 0);
		digestsize = 20;
		break;
	case SAB_AUTH_HMAC_SHA2_224:
		atfm = crypto_alloc_ahash("sha224", 0, 0);
		/*
		 * The final hash size of sha224 is 28 bytes, but for intermediate calculate
		 * the digest size is same as sha256, so it's 32 bytes.
		 */
		digestsize = 32;
		break;
	case SAB_AUTH_HMAC_SHA2_256:
		atfm = crypto_alloc_ahash("sha256", 0, 0);
		digestsize = 32;
		break;
	case SAB_AUTH_HMAC_SHA2_384:
		atfm = crypto_alloc_ahash("sha384", 0, 0);
		/* As sha224, the digest size of sha384 is the size of sha512 */
		digestsize = 64;
		break;
	case SAB_AUTH_HMAC_SHA2_512:
		atfm = crypto_alloc_ahash("sha512", 0, 0);
		digestsize = 64;
		break;
	default:
		CRYPTO_ERR("Unknown HMAC algorithm\n");
		return false;
	}

	if (IS_ERR(atfm)) {
		pr_err("%s: hash: failed to allocate atfm\n", __func__);
		return false;
	}

	blocksize = crypto_ahash_blocksize(atfm);
	state = kzalloc(crypto_ahash_statesize(atfm), GFP_KERNEL);
	if (!state)
		goto free_ahash;

	areq = ahash_request_alloc(atfm, GFP_KERNEL);
	if (!areq)
		goto free_ahash;

	crypto_ahash_clear_flags(atfm, ~0);

	memset(hashed_key, 0, blocksize);
	if (AuthKeyByteCount <= blocksize) {
		memcpy(hashed_key, AuthKey_p, AuthKeyByteCount);
	} else {
		if (!crypto_basic_hash(areq, AuthKey_p, AuthKeyByteCount, hashed_key, true))
			goto free_request;
	}

	for (i = 0; i < blocksize; i++)
		pad_block[i] = hashed_key[i] ^ 0x36;

	if (!crypto_basic_hash(areq, pad_block, blocksize, state, false))
		goto free_request;
	memcpy(Inner_p, state, digestsize);
	mtk_crypto_hash_byteswap(AuthAlgo, Inner_p, digestsize);

	for (i = 0; i < blocksize; i++)
		pad_block[i] = hashed_key[i] ^ 0x5c;

	if (!crypto_basic_hash(areq, pad_block, blocksize, state, false))
		goto free_request;
	memcpy(Outer_p, state, digestsize);
	mtk_crypto_hash_byteswap(AuthAlgo, Outer_p, digestsize);

	ret = true;

free_request:
	ahash_request_free(areq);
free_ahash:
	crypto_free_ahash(atfm);
	kfree(state);

	return ret;
}

static bool
mtk_ddk_aes_block_encrypt(uint8_t *key,  unsigned int klen, uint8_t *input, uint8_t *output)
{
	struct crypto_skcipher *tfm;
	struct skcipher_request *req = NULL;
	struct scatterlist src, dst;
	int ret = 0;
	void *iv = NULL;
	bool val = false;
	DECLARE_CRYPTO_WAIT(wait);

	tfm = crypto_alloc_skcipher("ecb(aes)", 0, 0);
	if (IS_ERR(tfm)) {
		pr_err("skcipher: failed to allocate tfm\n");
		return false;
	}

	req = skcipher_request_alloc(tfm, GFP_KERNEL);
	if (!req) {
		pr_err("skcipher: failed to allocate request\n");
		goto out;
	}

	ret = crypto_skcipher_setkey(tfm, key, klen);
	if (ret) {
		pr_err("skcipher: setkey failed\n");
		goto out;
	}

	sg_init_one(&src, input, AES_BLOCK_SIZE);
	sg_init_one(&dst, output, AES_BLOCK_SIZE);

	skcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG, crypto_req_done, &wait);
	skcipher_request_set_crypt(req, &src, &dst, AES_BLOCK_SIZE, iv);
	ret = crypto_skcipher_encrypt(req);
	ret = crypto_wait_req(ret, &wait);
	if (ret) {
		pr_notice("aead failed to encrypt/decrypt: %d\n", ret);
		goto out;
	}

	val = true;
out:
	skcipher_request_free(req);
	crypto_free_skcipher(tfm);

	return val;
}

static bool set_crypto_aead(struct xfrm_algo_aead *aead, SABuilder_Params_t *params)
{
	params->Key_p = aead->alg_key;
	params->CryptoAlgo = SAB_CRYPTO_AES;
	params->KeyByteCount = aead->alg_key_len / 8;
	if (strcmp(aead->alg_name, "rfc4106(gcm(aes))") == 0) {
		params->CryptoMode = SAB_CRYPTO_MODE_GCM;
		params->KeyByteCount = (aead->alg_key_len / 8) - CTR_RFC3686_NONCE_SIZE;
		params->Nonce_p = aead->alg_key + params->KeyByteCount;
	} else if (strcmp(aead->alg_name, "rfc4543(gcm(aes))") == 0) {
		params->CryptoMode = SAB_CRYPTO_MODE_GMAC;
		params->KeyByteCount = (aead->alg_key_len / 8) - CTR_RFC3686_NONCE_SIZE;
		params->Nonce_p = aead->alg_key + params->KeyByteCount;
	} else if (strcmp(aead->alg_name, "rfc4309(ccm(aes))") == 0) {
		params->CryptoMode = SAB_CRYPTO_MODE_CCM;
		params->KeyByteCount = (aead->alg_key_len / 8) - 3;
		params->Nonce_p = aead->alg_key + params->KeyByteCount;
	} else
		return false;

	return true;
}

static bool set_crypto_ealg(struct xfrm_algo *ealg, SABuilder_Params_t *params)
{
	params->CryptoMode = SAB_CRYPTO_MODE_CBC;
	params->KeyByteCount = ealg->alg_key_len / 8;
	params->Key_p = ealg->alg_key;
	if (strcmp(ealg->alg_name, "cbc(des)") == 0)
		params->CryptoAlgo = SAB_CRYPTO_DES;
	else if (strcmp(ealg->alg_name, "cbc(aes)") == 0)
		params->CryptoAlgo = SAB_CRYPTO_AES;
	else if (strcmp(ealg->alg_name, "cbc(des3_ede)") == 0)
		params->CryptoAlgo = SAB_CRYPTO_3DES;
	else
		return false;

	return true;
}

static bool set_auth_aead(struct xfrm_algo_aead *aead,
			  struct mtk_xfrm_params *xfrm_params,
			  SABuilder_Params_t *params, uint8_t **hash_key)
{
	uint8_t *key;
	uint8_t t;
	unsigned int i;

	xfrm_params->tr_type = EIP197_SMALL_TR;
	if (strcmp(aead->alg_name, "rfc4106(gcm(aes))") == 0) {
		params->AuthAlgo = SAB_AUTH_AES_GCM;
	} else if (strcmp(aead->alg_name, "rfc4543(gcm(aes))") == 0) {
		params->AuthAlgo = SAB_AUTH_AES_GMAC;
	} else if (strcmp(aead->alg_name, "rfc4309(ccm(aes))") == 0) {
		params->AuthAlgo = SAB_AUTH_AES_CCM;
		return true;
	} else {
		return false;
	}

	/* GHASH key: AES-ECB of an all-zero block */
	key = kzalloc(AES_BLOCK_SIZE, GFP_KERNEL);
	if (!key)
		return false;
	if (!mtk_ddk_aes_block_encrypt(params->Key_p, params->KeyByteCount, key, key)) {
		kfree(key);
		return false;
	}

	/* Byte-swap the hash key */
	for (i = 0; i < 4; i++) {
		t = key[4*i+3];
		key[4*i+3] = key[4*i];
		key[4*i] = t;
		t = key[4*i+2];
		key[4*i+2] = key[4*i+1];
		key[4*i+1] = t;
	}

	params->AuthKey1_p = key;
	*hash_key = key;

	return true;
}

static bool set_auth_aalg(struct xfrm_algo_auth *aalg,
			  struct mtk_xfrm_params *xfrm_params,
			  SABuilder_Params_t *params, uint8_t **inner, uint8_t **outer)
{
	SABuilder_Auth_t algo;
	unsigned int digest;
	u32 tr_type = EIP197_SMALL_TR;

	if (strcmp(aalg->alg_name, "hmac(sha1)") == 0) {
		algo = SAB_AUTH_HMAC_SHA1;
		digest = SHA1_DIGEST_SIZE;
	} else if (strcmp(aalg->alg_name, "hmac(sha256)") == 0) {
		algo = SAB_AUTH_HMAC_SHA2_256;
		digest = SHA256_DIGEST_SIZE;
	} else if (strcmp(aalg->alg_name, "hmac(sha384)") == 0) {
		algo = SAB_AUTH_HMAC_SHA2_384;
		digest = SHA512_DIGEST_SIZE;
		tr_type = EIP197_LARGE_TR;
	} else if (strcmp(aalg->alg_name, "hmac(sha512)") == 0) {
		algo = SAB_AUTH_HMAC_SHA2_512;
		digest = SHA512_DIGEST_SIZE;
		tr_type = EIP197_LARGE_TR;
	} else if (strcmp(aalg->alg_name, "hmac(md5)") == 0) {
		algo = SAB_AUTH_HMAC_MD5;
		digest = MD5_DIGEST_SIZE;
	} else {
		return false;
	}

	*inner = kzalloc(digest, GFP_KERNEL);
	*outer = kzalloc(digest, GFP_KERNEL);
	if (!*inner || !*outer)
		return false;

	if (!crypto_hmac_precompute(algo, &aalg->alg_key[0], aalg->alg_key_len / 8,
				    *inner, *outer))
		return false;

	params->AuthAlgo = algo;
	params->AuthKey1_p = *inner;
	params->AuthKey2_p = *outer;
	xfrm_params->tr_type = tr_type;

	return true;
}

void *mtk_ddk_tr_ipsec_build(struct mtk_xfrm_params *xfrm_params, u32 ipsec_mode)
{
	struct xfrm_state *xs = xfrm_params->xs;
	SABuilder_Params_IPsec_t ipsec_params;
	SABuilder_Status_t sa_status;
	SABuilder_Params_t params;
	bool set_success = false;
	unsigned int SAWords = 0;
	uint8_t *inner = NULL;
	uint8_t *outer = NULL;

	DMABuf_Status_t dma_status;
	DMABuf_Properties_t dma_properties = {0, 0, 0, 0};
	DMABuf_HostAddress_t sa_host_addr;

	DMABuf_Handle_t sa_handle = {0};
	PEC_Status_t pec_status;

	if (xs->props.family == AF_INET)
		sa_status = SABuilder_Init_ESP(&params,
					&ipsec_params,
					be32_to_cpu(xs->id.spi),
					ipsec_mode,
					SAB_IPSEC_IPV4,
					xfrm_params->dir);
	else
		sa_status = SABuilder_Init_ESP(&params,
					&ipsec_params,
					be32_to_cpu(xs->id.spi),
					ipsec_mode,
					SAB_IPSEC_IPV6,
					xfrm_params->dir);

	if (sa_status != SAB_STATUS_OK) {
		pr_err("SABuilder_Init_ESP failed\n");
		sa_host_addr.p = NULL;
		goto error_ret;
	}

	/* Check algorithm exist in xfrm state*/
	if (!xs->aead && (!xs->ealg || !xs->aalg)) {
		CRYPTO_ERR("NULL algorithm in xfrm state\n");
		sa_host_addr.p = NULL;
		goto error_ret;
	}

	/* Add crypto key and parameters */
	if (xs->aead)
		set_success = set_crypto_aead(xs->aead, &params);
	else
		set_success = set_crypto_ealg(xs->ealg, &params);
	if (set_success != true) {
		CRYPTO_ERR("Set Crypto Algo failed\n");
		sa_host_addr.p = NULL;
		goto error_ret;
	}

	/* Add authentication key and parameters */
	if (xs->aead)
		set_success = set_auth_aead(xs->aead, xfrm_params, &params, &inner);
	else
		set_success = set_auth_aalg(xs->aalg, xfrm_params, &params, &inner, &outer);
	if (set_success != true) {
		CRYPTO_ERR("Set Auth Algo failed\n");
		sa_host_addr.p = NULL;
		goto error_ret;
	}

	if (xs->encap) {
		ipsec_params.IPsecFlags |= SAB_IPSEC_NATT;
		ipsec_params.NATTSrcPort = be16_to_cpu(xs->encap->encap_sport);
		ipsec_params.NATTDestPort = be16_to_cpu(xs->encap->encap_dport);
	}

	ipsec_params.IPsecFlags |= (SAB_IPSEC_PROCESS_IP_HEADERS
				    | SAB_IPSEC_EXT_PROCESSING);
	if (ipsec_mode == SAB_IPSEC_TUNNEL) {
		if (xs->props.family == AF_INET) {
			ipsec_params.SrcIPAddr_p = (uint8_t *) &xs->props.saddr.a4;
			ipsec_params.DestIPAddr_p = (uint8_t *) &xs->id.daddr.a4;
		} else {
			ipsec_params.SrcIPAddr_p = (uint8_t *) &xs->props.saddr.a6;
			ipsec_params.DestIPAddr_p = (uint8_t *) &xs->id.daddr.a6;
		}
	}

	if (xs->aead)
		ipsec_params.ICVByteCount = xs->aead->alg_icv_len / 8;
	else
		ipsec_params.ICVByteCount = xs->aalg->alg_trunc_len / 8;

	sa_status = SABuilder_GetSizes(&params, &SAWords, NULL, NULL);
	if (sa_status != SAB_STATUS_OK) {
		CRYPTO_ERR("SA not created because of size errors\n");
		sa_host_addr.p = NULL;
		goto error_ret;
	}

	dma_properties.fCached = true;
	dma_properties.Alignment = MTK_EIP197_INLINE_DMA_ALIGNMENT_BYTE_COUNT;
	dma_properties.Bank = MTK_EIP197_INLINE_BANK_TRANSFORM;
	dma_properties.Size = SAWords * sizeof(u32);

	dma_status = DMABuf_Alloc(dma_properties, &sa_host_addr, &sa_handle);
	if (dma_status != DMABUF_STATUS_OK) {
		CRYPTO_ERR("Allocation of SA failed\n");
		sa_host_addr.p = NULL;
		goto error_ret;
	}

	sa_status = SABuilder_BuildSA(&params, (u32 *) sa_host_addr.p, NULL, NULL);
	if (sa_status != SAB_STATUS_OK) {
		CRYPTO_ERR("SA not created because of errors\n");
		DMABuf_Release(sa_handle);
		sa_host_addr.p = NULL;
		goto error_ret;
	}

	pec_status = PEC_SA_Register(0, sa_handle, DMABuf_NULLHandle, DMABuf_NULLHandle);
	if (pec_status != PEC_STATUS_OK) {
		CRYPTO_ERR("%s: PEC_SA_Register failed\n", __func__);
		DMABuf_Release(sa_handle);
		sa_host_addr.p = NULL;
		goto error_ret;
	}

	xfrm_params->p_handle = sa_handle.p;

error_ret:
	kfree(inner);
	kfree(outer);
	return sa_host_addr.p;
}

int mtk_ddk_pec_init(void)
{
	PEC_InitBlock_t pec_init_blk = {0, 0, false};
	PEC_Capabilities_t pec_cap;
	PEC_Status_t pec_sta;
	PCL_Status_t pcl_sta;
	u32 tries;
	u32 j;

	pcl_sta = PCL_Init(PCL_INTERFACE_ID, 1);
	if (pcl_sta != PCL_STATUS_OK) {
		CRYPTO_ERR("PCL could not be initialized, error=%d\n", pcl_sta);
		return -EIO;
	}

	pcl_sta = PCL_DTL_Init(PCL_INTERFACE_ID);
	if (pcl_sta != PCL_STATUS_OK) {
		CRYPTO_ERR("PCL-DTL could not be initialized, error=%d\n", pcl_sta);
		goto err_pcl_uninit;
	}

	for (j = 0; j < PEC_MAX_INTERFACE_NUM; j++) {
		tries = MTK_EIP197_INLINE_NOF_TRIES;

		while (tries) {
			pec_sta = PEC_Init(j, &pec_init_blk);
			if (pec_sta == PEC_STATUS_OK) {
				CRYPTO_INFO("PEC_INIT interface %d ok!\n", j);
				break;
			}
			if (pec_sta != PEC_STATUS_BUSY) {
				CRYPTO_ERR("PEC interface %u init error %d\n", j, pec_sta);
				goto err_pec_uninit;
			}

			mdelay(MTK_EIP197_INLINE_RETRY_DELAY_MS);
			tries--;
		}

		if (!tries) {
			CRYPTO_ERR("PEC interface %u could not be initialized\n", j);
			goto err_pec_uninit;
		}
	}

	pec_sta = PEC_Capabilities_Get(&pec_cap);
	if (pec_sta != PEC_STATUS_OK) {
		CRYPTO_ERR("PEC capability could not be obtained: %d\n", pec_sta);
		goto err_pec_uninit;
	}

	CRYPTO_INFO("PEC Capabilities: %s\n", pec_cap.szTextDescription);

	return 0;

err_pec_uninit:
	while (j--)
		PEC_UnInit(j);
	PCL_DTL_UnInit(PCL_INTERFACE_ID);
err_pcl_uninit:
	PCL_UnInit(PCL_INTERFACE_ID);

	return -EIO;
}

void mtk_ddk_pec_deinit(void)
{
	unsigned int tries;
	PEC_Status_t pec_sta;
	int j;

	for (j = 0; j < PEC_MAX_INTERFACE_NUM; j++) {
		tries = MTK_EIP197_INLINE_NOF_TRIES;

		while (tries) {
			pec_sta = PEC_UnInit(j);
			if (pec_sta == PEC_STATUS_OK)
				break;
			if (pec_sta != PEC_STATUS_BUSY) {
				CRYPTO_ERR("PEC interface %d could not deinit, error=%d\n",
					   j, pec_sta);
				break;
			}

			mdelay(MTK_EIP197_INLINE_RETRY_DELAY_MS);
			tries--;
		}

		if (!tries)
			CRYPTO_ERR("PEC interface %d could not be un-initialized, timeout\n", j);
	}

	PCL_DTL_UnInit(PCL_INTERFACE_ID);
	PCL_UnInit(PCL_INTERFACE_ID);
}

bool
mtk_ddk_invalidate_rec(
		void *sa_p,
		const bool IsTransform)
{
	PEC_Status_t PEC_Rc;
	PEC_CommandDescriptor_t Cmd;
	PEC_ResultDescriptor_t Res;
	unsigned int count;
	IOToken_Input_Dscr_t InTokenDscr;
	IOToken_Output_Dscr_t OutTokenDscr;
	uint32_t InputToken[IOTOKEN_IN_WORD_COUNT_IL];
	uint32_t OutputToken[IOTOKEN_OUT_WORD_COUNT_IL];
	void *InTokenDscrExt_p = NULL;
	void *OutTokenDscrExt_p = NULL;
	IOToken_Input_Dscr_Ext_t InTokenDscrExt;
	IOToken_Output_Dscr_Ext_t OutTokenDscrExt;
	DMABuf_Handle_t Rec_p;

	Rec_p.p = sa_p;
	ZEROINIT(InTokenDscrExt);
	InTokenDscrExt_p = &InTokenDscrExt;
	OutTokenDscrExt_p = &OutTokenDscrExt;

	ZEROINIT(InTokenDscr);

	// Fill in the command descriptor for the Invalidate command
	ZEROINIT(Cmd);

	Cmd.SrcPkt_Handle    = DMABuf_NULLHandle;
	Cmd.DstPkt_Handle    = DMABuf_NULLHandle;
	Cmd.SA_Handle1       = Rec_p;
	Cmd.SA_Handle2       = DMABuf_NULLHandle;
	Cmd.Token_Handle     = DMABuf_NULLHandle;
	Cmd.SrcPkt_ByteCount = 0;

#if defined(IOTOKEN_USE_HW_SERVICE)
	if (IsTransform)
		InTokenDscrExt.HW_Services = IOTOKEN_CMD_INV_TR;
	else
		InTokenDscrExt.HW_Services = IOTOKEN_CMD_INV_FR;
#endif

	if (!crypto_iotoken_create(&InTokenDscr, InTokenDscrExt_p, InputToken, &Cmd))
		return false;

	// Issue command
	do {
		PEC_Rc = PEC_Packet_Put(PEC_INTERFACE_ID, &Cmd, 1, &count);
	} while (PEC_Rc == PEC_STATUS_BUSY);

	if (PEC_Rc != PEC_STATUS_OK || count != 1) {
		CRYPTO_ERR("%s: PEC_Packet_Put() error %d, count %d\n",
				 __func__,
				 PEC_Rc,
				 count);
		return false;
	}

	// Receive the result packet ... do we care about contents ?
	if (crypto_pe_busy_get_one(&OutTokenDscr, OutputToken, &Res, PEC_INTERFACE_ID) < 1) {
		CRYPTO_ERR("%s: crypto_pe_busy_get_one() failed\n", __func__);
		return false;
	}

	return true;
}
