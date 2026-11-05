/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2023 MediaTek Inc.
 *
 * Author: Chris.Chou <chris.chou@mediatek.com>
 *         Ren-Ting Wang <ren-ting.wang@mediatek.com>
 */

#ifndef _CRYPTO_EIP_DDK_WRAPPER_H_
#define _CRYPTO_EIP_DDK_WRAPPER_H_

#include "crypto-eip/crypto-eip.h"
#include "crypto-eip/crypto-eip197-inline-ddk.h"

void *mtk_ddk_tr_ipsec_build(struct mtk_xfrm_params *xfrm_params, u32 ipsec_mod);
bool crypto_hmac_precompute(SABuilder_Auth_t AuthAlgo,
			    uint8_t *AuthKey_p,
			    unsigned int AuthKeyByteCount,
			    uint8_t *Inner_p,
			    uint8_t *Outer_p);
void crypto_free_sa(void *sa_pointer, int ring);
bool mtk_ddk_invalidate_rec(void *sa_p, const bool IsTransform);

int mtk_ddk_pec_init(void);
void mtk_ddk_pec_deinit(void);
#endif /* _CRYPTO_EIP_DDK_WRAPPER_H_ */
