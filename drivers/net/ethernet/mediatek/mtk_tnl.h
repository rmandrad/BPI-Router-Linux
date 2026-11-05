/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2026 MediaTek Inc.
 *
 * Tunnel descriptor the MediaTek offload engines (NPU, EIP-197) keep in the
 * headroom of an skb.
 */

#ifndef MTK_TNL_H
#define MTK_TNL_H

#include <linux/in.h>
#include <linux/skbuff.h>

struct mtk_tnl_desc {
	u32 entry : 15;
	u32 filled : 3;
	u32 crsn : 5;
	u32 resv1 : 3;
	u32 sport : 4;
	u32 resv2 : 1;
	u32 alg : 1;
	u32 iface : 8;
	u32 wdmaid : 2;
	u32 rxid : 2;
	u32 wcid : 16;
	u32 bssid : 8;
	u32 usr_info : 16;
	u32 tid : 4;
	u32 is_fixedrate : 1;
	u32 is_prior : 1;
	u32 is_sp : 1;
	u32 hf : 1;
	u32 amsdu : 1;
	u32 tops : 6;
	u32 is_decap : 1;
	u32 cdrt : 8;
	u32 is_decrypt : 1;
	u32 is_pppoe : 1;
	u32 resv3 : 2;
	u32 magic_tag_protect : 16;
} __packed;

#define TNL_MAGIC_TAG 0x6789
#define skb_tnl_cdrt(skb) (((struct mtk_tnl_desc *)((skb)->head))->cdrt)
#define skb_tnl_tops(skb) (((struct mtk_tnl_desc *)((skb)->head))->tops)
#define skb_tnl_set_cdrt(skb, cdrt) ((skb_tnl_cdrt(skb)) = (cdrt))
#define skb_tnl_magic_tag(skb) (((struct mtk_tnl_desc *)((skb)->head))->magic_tag_protect)
#define is_tnl_tag_valid(skb) (skb_tnl_magic_tag(skb) == TNL_MAGIC_TAG)
#define skb_tnl_is_pppoe(skb) (((struct mtk_tnl_desc *)((skb)->head))->is_pppoe)


/* True when the skb was marked for the EIP-197 by the crypto-eip-inline
 * driver (xfrm packet offload). The marker is skb->inner_protocol == ESP
 * together with a valid tunnel descriptor in the headroom; both must hold
 * because the descriptor does not survive every skb copy.
 */
static inline bool mtk_tnl_esp_tagged(const struct sk_buff *skb)
{
	return unlikely(skb->inner_protocol == IPPROTO_ESP) &&
	       skb_headroom(skb) >= sizeof(struct mtk_tnl_desc) &&
	       is_tnl_tag_valid(skb) && skb_tnl_cdrt(skb);
}

/* Carry the tunnel descriptor over to skbs that were split off @old (GSO
 * segments), so the segments are still sent through the EIP-197 instead of
 * leaving as plain text.
 */
static inline int mtk_skb_copy_head(struct sk_buff *new, struct sk_buff *old)
{
	bool esp = mtk_tnl_esp_tagged(old);
	struct sk_buff *temp;

	if (!esp)
		return 0;

	for (temp = new; temp; temp = temp->next) {
		if (skb_cow_head(temp, skb_headroom(old)))
			return -ENOMEM;

		memcpy(temp->head, old->head, sizeof(struct mtk_tnl_desc));
		temp->inner_protocol = IPPROTO_ESP;
	}

	return 0;
}

#endif /* MTK_TNL_H */
