/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2023 MediaTek Inc.
 *
 * Author: Chris.Chou <chris.chou@mediatek.com>
 *         Ren-Ting Wang <ren-ting.wang@mediatek.com>
 */

#ifndef _CRYPTO_EIP_H_
#define _CRYPTO_EIP_H_

#include <linux/atomic.h>
#include <linux/io.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <crypto/sha1.h>
#include <crypto/sha2.h>
#include <net/xfrm.h>

#include "crypto-eip/crypto-eip197-inline-ddk.h"

struct cdrt_entry;
struct mtk_eth;

#define EIP197_SMALL_TR			2
#define EIP197_LARGE_TR			3

#define EIP197_FORCE_CLK_ON2		(0xfffd8)
#define EIP197_FORCE_CLK_ON		(0xfffe8)

#define PEC_PCL_EIP197

struct mtk_crypto {
	struct mtk_eth *eth;
	void __iomem *crypto_base;
	u32 ppe_num;
};

extern struct mtk_crypto mcrypto;
extern int mac_filter_enable;

struct mtk_xfrm_params {
	struct xfrm_state *xs;
	struct list_head node;
	struct cdrt_entry *cdrt;

	void *p_tr;			/* pointer to transform record */
	u32 tr_type;
	void *p_handle;			/* pointer to eip dma handle */
	u32 dir;			/* SABuilder_Direction_t */
	atomic64_t bytes;		/* total bytes applied */
	atomic64_t packets;		/* total packets applied */
};

struct xfrm_params_list {
	struct list_head list;
	spinlock_t lock;
};

struct xfrm_params_list *mtk_xfrm_params_list_get(void);

/* cdrt index of an offloaded state, 0 if @xs is not offloaded */
int mtk_crypto_xfrm_get_cdrt(struct xfrm_state *xs);
void mtk_crypto_decrypt_sec_path_setup(struct sk_buff *skb, u16 cdrt);

bool mtk_crypto_dev_supported(struct net_device *dev);
void mtk_crypto_enable_ipsec_dev_features(struct net_device *dev);
void mtk_crypto_disable_ipsec_dev_features(struct net_device *dev);
int mtk_crypto_enable_all_dev_features(void);
void mtk_crypto_disable_all_dev_features(void);
u32 mtk_crypto_ppe_get_num(struct net_device *dev);

/* xfrm callbacks */
int mtk_xfrm_offload_state_add(struct net_device *dev, struct xfrm_state *xs,
			       struct netlink_ext_ack *extack);
void mtk_xfrm_offload_state_delete(struct net_device *dev, struct xfrm_state *xs);
void mtk_xfrm_offload_state_free(struct net_device *dev, struct xfrm_state *xs);
int mtk_xfrm_offload_policy_add(struct xfrm_policy *xp, struct netlink_ext_ack *extack);
void mtk_xfrm_offload_policy_delete(struct xfrm_policy *xp);
void mtk_xfrm_offload_policy_free(struct xfrm_policy *xp);
bool mtk_xfrm_offload_ok(struct sk_buff *skb, struct xfrm_state *xs);

int mtk_xfrm_offload_init(void);
void mtk_xfrm_offload_exit(void);
#endif /* _CRYPTO_EIP_H_ */
