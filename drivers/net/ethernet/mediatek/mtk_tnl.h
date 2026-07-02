/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef MTK_TNL_H
#define MTK_TNL_H

#include <linux/skbuff.h>
#include <linux/types.h>

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
	u32 resv3 : 4;
	u32 magic_tag_protect : 16;
} __packed;

#define TNL_MAGIC_TAG			0x6789
#define skb_tnl_cdrt(skb)		(((struct mtk_tnl_desc *)((skb)->head))->cdrt)
#define skb_tnl_set_cdrt(skb, cdrt)	((skb_tnl_cdrt(skb)) = (cdrt))
#define skb_tnl_magic_tag(skb)		(((struct mtk_tnl_desc *)((skb)->head))->magic_tag_protect)
#define is_tnl_tag_valid(skb)		(skb_tnl_magic_tag(skb) == TNL_MAGIC_TAG)

#endif /* MTK_TNL_H */
