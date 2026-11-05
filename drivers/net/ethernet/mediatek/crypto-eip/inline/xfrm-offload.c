// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2023 MediaTek Inc.
 *
 * Author: Chris.Chou <chris.chou@mediatek.com>
 *         Ren-Ting Wang <ren-ting.wang@mediatek.com>
 *
 * xfrm packet offload on the EIP-197.
 *
 * Outbound: xfrm_output() calls mtk_xfrm_offload_ok() for every packet of an
 * offloaded state. It marks the packet (tunnel descriptor in the skb
 * headroom, skb->inner_protocol == ESP) so mtk_eth_soc sends it through the
 * EIP-197, which encrypts it according to the CDRT entry of the state. A
 * packet that cannot be marked is refused (xfrm drops it); it must never be
 * sent on as plain text.
 *
 * Inbound: the PCE classifies ESP packets of an offloaded state to the
 * EIP-197, which decrypts them. mtk_eth_soc reports the CDRT index in the RX
 * descriptor and mtk_crypto_decrypt_sec_path_setup() attaches the state to
 * the skb so the xfrm policy check accepts the plain packet.
 */

#include <linux/bitops.h>
#include <linux/etherdevice.h>
#include <linux/list.h>
#include <linux/types.h>
#include <linux/if_arp.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/workqueue.h>
#include <net/arp.h>
#include <net/dsa.h>
#include <net/ip6_route.h>
#include <net/ndisc.h>
#include <net/neighbour.h>
#include <net/route.h>
#include <net/netfilter/nf_flow_table.h>

#include <mtk_eth_soc.h>
#include <mtk_ppe.h>
#include <mtk_tnl.h>

#include <pce/cdrt.h>
#include <pce/cls.h>
#include <pce/netsys.h>
#include <pce/pce.h>

#include "crypto-eip/crypto-eip.h"
#include "crypto-eip/ddk-wrapper.h"
#include "crypto-eip/internal.h"

static struct xfrm_params_list xfrm_params_list = {
	.list = LIST_HEAD_INIT(xfrm_params_list.list),
	.lock = __SPIN_LOCK_UNLOCKED(xfrm_params_list.lock),
};

static struct workqueue_struct *mtk_xfrm_wq;

struct mtk_xfrm_teardown_work {
	struct work_struct work;
	u32 cdrt_idx;
};

struct xfrm_params_list *mtk_xfrm_params_list_get(void)
{
	return &xfrm_params_list;
}

/* True if @dev can send packets to the EIP-197: a MediaTek Ethernet MAC or a
 * DSA user port on top of one. Anything else would send the packet on as plain
 * text, so a state on such a device must be refused.
 */
bool mtk_crypto_dev_supported(struct net_device *dev)
{
	struct net_device *lower = dev;

	if (!dev || !mcrypto.eth)
		return false;

#if IS_ENABLED(CONFIG_NET_DSA)
	if (dsa_user_dev_check(dev)) {
		struct dsa_port *dp = dsa_port_from_netdev(dev);

		if (IS_ERR(dp) || !dp->cpu_dp)
			return false;

		lower = dp->cpu_dp->conduit;
	}
#endif

	return lower->dev.parent == mcrypto.eth->dev;
}

/* cdrt index of @xs, 0 if it is not (or no longer) offloaded */
int mtk_crypto_xfrm_get_cdrt(struct xfrm_state *xs)
{
	struct mtk_xfrm_params *xfrm_params;
	struct mtk_xfrm_params *temp;
	int idx = 0;

	xfrm_params = (struct mtk_xfrm_params *)xs->xso.offload_handle;
	if (!xfrm_params)
		return 0;

	spin_lock_bh(&xfrm_params_list.lock);
	list_for_each_entry(temp, &xfrm_params_list.list, node) {
		if (xfrm_params == temp) {
			idx = xfrm_params->cdrt->idx;
			break;
		}
	}
	spin_unlock_bh(&xfrm_params_list.lock);

	return idx;
}

void mtk_crypto_decrypt_sec_path_setup(struct sk_buff *skb, u16 cdrt)
{
	struct mtk_xfrm_params *xfrm_params;
	struct xfrm_state *x = NULL;
	struct xfrm_offload *xo;
	struct sec_path *sp;

	if (!cdrt)
		return;

	spin_lock_bh(&xfrm_params_list.lock);
	list_for_each_entry(xfrm_params, &xfrm_params_list.list, node) {
		if (cdrt != xfrm_params->cdrt->idx)
			continue;

		if (xfrm_params->xs->km.state == XFRM_STATE_VALID &&
		    xfrm_params->xs->xso.type == XFRM_DEV_OFFLOAD_PACKET &&
		    xfrm_params->xs->xso.dir == XFRM_DEV_OFFLOAD_IN) {
			x = xfrm_params->xs;
			xfrm_state_hold(x);
			atomic64_add(skb->len, &xfrm_params->bytes);
			atomic64_inc(&xfrm_params->packets);
		}
		break;
	}
	spin_unlock_bh(&xfrm_params_list.lock);

	if (!x)
		return;

	/* only attach secpath for resolved states, an empty secpath
	 * (len == 0) makes xfrm_input_state() read xvec[-1]
	 */
	sp = secpath_set(skb);
	if (!sp || sp->len >= XFRM_MAX_OFFLOAD_DEPTH) {
		xfrm_state_put(x);
		return;
	}

	sp->xvec[sp->len++] = x;
	sp->olen++;
	xo = xfrm_offload(skb);
	if (!xo) {
		/* drops the reference taken above with the secpath */
		secpath_reset(skb);
		return;
	}
	xo->flags = CRYPTO_DONE;
	xo->status = CRYPTO_SUCCESS;
}

static void mtk_xfrm_offload_cdrt_tear_down(struct mtk_xfrm_params *xfrm_params)
{
	if (!xfrm_params->cdrt)
		return;

	memset(&xfrm_params->cdrt->desc, 0, sizeof(struct cdrt_desc));

	mtk_pce_cdrt_entry_write(xfrm_params->cdrt);
}

static int mtk_xfrm_offload_cdrt_setup(struct mtk_xfrm_params *xfrm_params)
{
	struct cdrt_desc *cdesc = &xfrm_params->cdrt->desc;

	cdesc->desc1.common.type = 3;
	cdesc->desc1.token_len = 48;
	cdesc->desc1.p_tr[0] = __pa(xfrm_params->p_tr) | xfrm_params->tr_type;
	cdesc->desc1.p_tr[1] = __pa(xfrm_params->p_tr) >> 32 & 0xFFFFFFFF;

	cdesc->desc2.hw_srv = 3;
	cdesc->desc2.allow_pad = 1;
	cdesc->desc2.strip_pad = 1;

	return mtk_pce_cdrt_entry_write(xfrm_params->cdrt);
}

static void mtk_xfrm_offload_cls_entry_tear_down(struct mtk_xfrm_params *xfrm_params)
{
	if (!xfrm_params->cdrt || !xfrm_params->cdrt->cls)
		return;

	memset(&xfrm_params->cdrt->cls->cdesc, 0, sizeof(struct cls_desc));

	mtk_pce_cls_entry_write(xfrm_params->cdrt->cls);

	mtk_pce_cls_entry_free(xfrm_params->cdrt->cls);
}

static int mtk_xfrm_offload_cls_entry_setup(struct net_device *dev,
					    struct mtk_xfrm_params *xfrm_params)
{
	struct cls_desc *cdesc;
	struct xfrm_state *xs = xfrm_params->xs;
	u32 ppe_port;

	xfrm_params->cdrt->cls = mtk_pce_cls_entry_alloc();
	if (IS_ERR(xfrm_params->cdrt->cls))
		return PTR_ERR(xfrm_params->cdrt->cls);

	cdesc = &xfrm_params->cdrt->cls->cdesc;

	if (mac_filter_enable) {
		CLS_DESC_DATA(cdesc, fport, PSE_PORT_TDMA);
		CLS_DESC_DATA(cdesc, tport_idx, 0x3);
	} else {
		ppe_port = mtk_crypto_ppe_get_num(dev);
		CLS_DESC_DATA(cdesc, fport, ppe_port);
		CLS_DESC_DATA(cdesc, tport_idx, 0x2);
	}
	CLS_DESC_DATA(cdesc, cdrt_idx, xfrm_params->cdrt->idx);

	if (xs->encap) {
		CLS_DESC_MASK_DATA(cdesc, tag,
				   CLS_DESC_TAG_MASK, CLS_DESC_TAG_MATCH_L4_USR);
		CLS_DESC_MASK_DATA(cdesc, l4_type,
				   CLS_DESC_L4_TYPE_MASK, IPPROTO_UDP);
		CLS_DESC_MASK_DATA(cdesc, l4_valid,
				   CLS_DESC_L4_VALID_MASK,
				   CLS_DESC_VALID_UPPER_HALF_WORD_BIT |
				   CLS_DESC_VALID_LOWER_HALF_WORD_BIT |
				   CLS_DESC_VALID_DPORT_BIT);
		CLS_DESC_MASK_DATA(cdesc, l4_dport, CLS_DESC_L4_DPORT_MASK,
				   be16_to_cpu(xs->encap->encap_dport));
	} else {
		CLS_DESC_MASK_DATA(cdesc, tag,
				   CLS_DESC_TAG_MASK, CLS_DESC_TAG_MATCH_L4_HDR);
		CLS_DESC_MASK_DATA(cdesc, l4_udp_hdr_nez,
				   CLS_DESC_UDPLITE_L4_HDR_NEZ_MASK,
				   CLS_DESC_UDPLITE_L4_HDR_NEZ_MASK);
		CLS_DESC_MASK_DATA(cdesc, l4_type,
				   CLS_DESC_L4_TYPE_MASK, IPPROTO_ESP);
		CLS_DESC_MASK_DATA(cdesc, l4_valid,
				   0x3,
				   CLS_DESC_VALID_UPPER_HALF_WORD_BIT |
				   CLS_DESC_VALID_LOWER_HALF_WORD_BIT);
	}

	CLS_DESC_MASK_DATA(cdesc, l4_hdr_usr_data,
			   0xFFFFFFFF, be32_to_cpu(xfrm_params->xs->id.spi));

	return mtk_pce_cls_entry_write(xfrm_params->cdrt->cls);
}

static void mtk_xfrm_offload_context_tear_down(struct mtk_xfrm_params *xfrm_params)
{
	mtk_xfrm_offload_cdrt_tear_down(xfrm_params);

	if (!xfrm_params->p_handle)
		return;

	mtk_ddk_invalidate_rec(xfrm_params->p_handle, true);
	crypto_free_sa(xfrm_params->p_handle, 0);
	xfrm_params->p_handle = NULL;
}

static int mtk_xfrm_offload_context_setup(struct mtk_xfrm_params *xfrm_params)
{
	void *tr;
	int ret;

	switch (xfrm_params->xs->outer_mode.encap) {
	case XFRM_MODE_TUNNEL:
		tr = mtk_ddk_tr_ipsec_build(xfrm_params, SAB_IPSEC_TUNNEL);
		break;
	case XFRM_MODE_TRANSPORT:
		tr = mtk_ddk_tr_ipsec_build(xfrm_params, SAB_IPSEC_TRANSPORT);
		break;
	default:
		return -EINVAL;
	}

	if (!tr)
		return -EINVAL;

	xfrm_params->p_tr = tr;

	ret = mtk_xfrm_offload_cdrt_setup(xfrm_params);
	if (ret)
		mtk_xfrm_offload_context_tear_down(xfrm_params);

	return ret;
}

static int mtk_xfrm_offload_state_add_outbound(struct xfrm_state *xs,
					       struct mtk_xfrm_params *xfrm_params)
{
	int ret;

	xfrm_params->cdrt = mtk_pce_cdrt_entry_alloc(CDRT_ENCRYPT);
	if (IS_ERR(xfrm_params->cdrt)) {
		ret = PTR_ERR(xfrm_params->cdrt);
		xfrm_params->cdrt = NULL;
		return ret;
	}

	xfrm_params->dir = SAB_DIRECTION_OUTBOUND;

	ret = mtk_xfrm_offload_context_setup(xfrm_params);
	if (ret)
		goto free_cdrt;

	return 0;

free_cdrt:
	mtk_pce_cdrt_entry_free(xfrm_params->cdrt);
	xfrm_params->cdrt = NULL;

	return ret;
}

static int mtk_xfrm_offload_state_add_inbound(struct net_device *dev,
					      struct xfrm_state *xs,
					      struct mtk_xfrm_params *xfrm_params)
{
	int ret;

	xfrm_params->cdrt = mtk_pce_cdrt_entry_alloc(CDRT_DECRYPT);
	if (IS_ERR(xfrm_params->cdrt)) {
		ret = PTR_ERR(xfrm_params->cdrt);
		xfrm_params->cdrt = NULL;
		return ret;
	}

	xfrm_params->dir = SAB_DIRECTION_INBOUND;

	ret = mtk_xfrm_offload_context_setup(xfrm_params);
	if (ret)
		goto free_cdrt;

	ret = mtk_xfrm_offload_cls_entry_setup(dev, xfrm_params);
	if (ret)
		goto tear_down_context;

	return 0;

tear_down_context:
	mtk_xfrm_offload_context_tear_down(xfrm_params);

free_cdrt:
	mtk_pce_cdrt_entry_free(xfrm_params->cdrt);
	xfrm_params->cdrt = NULL;

	return ret;
}

int mtk_xfrm_offload_state_add(struct net_device *dev, struct xfrm_state *xs,
			       struct netlink_ext_ack *extack)
{
	struct mtk_xfrm_params *xfrm_params;
	int ret;

	if (xs->xso.type != XFRM_DEV_OFFLOAD_PACKET) {
		NL_SET_ERR_MSG_MOD(extack, "only packet offload is supported");
		return -EOPNOTSUPP;
	}

	if (!mtk_crypto_dev_supported(dev)) {
		NL_SET_ERR_MSG_MOD(extack, "device is not driven by the MediaTek ethernet");
		return -EOPNOTSUPP;
	}

	if (xs->props.family != AF_INET && xs->props.family != AF_INET6) {
		NL_SET_ERR_MSG_MOD(extack, "only IPv4 and IPv6 states can be offloaded");
		return -EINVAL;
	}

	if (xs->id.proto != IPPROTO_ESP) {
		NL_SET_ERR_MSG_MOD(extack, "only ESP can be offloaded");
		return -EINVAL;
	}

	if (xs->outer_mode.encap != XFRM_MODE_TUNNEL &&
	    xs->outer_mode.encap != XFRM_MODE_TRANSPORT) {
		NL_SET_ERR_MSG_MOD(extack, "only tunnel and transport mode can be offloaded");
		return -EINVAL;
	}

	/* the engine keeps its own 32 bit sequence number context */
	if (xs->replay_esn) {
		NL_SET_ERR_MSG_MOD(extack, "ESN is not supported");
		return -EOPNOTSUPP;
	}

	/* the module must not go away while the engine holds state for us */
	if (!try_module_get(THIS_MODULE))
		return -ENODEV;

	xfrm_params = kzalloc(sizeof(*xfrm_params), GFP_KERNEL);
	if (!xfrm_params) {
		ret = -ENOMEM;
		goto err_put_module;
	}

	xfrm_params->xs = xs;
	INIT_LIST_HEAD(&xfrm_params->node);

	if (xs->xso.dir == XFRM_DEV_OFFLOAD_IN)
		ret = mtk_xfrm_offload_state_add_inbound(dev, xs, xfrm_params);
	else
		ret = mtk_xfrm_offload_state_add_outbound(xs, xfrm_params);
	if (ret) {
		NL_SET_ERR_MSG_MOD(extack, "no engine resources or unsupported algorithm");
		goto err_free;
	}

	xs->xso.offload_handle = (unsigned long)xfrm_params;

	if (extack) {
		memcpy(extack->cookie, &xfrm_params->cdrt->idx,
		       sizeof(xfrm_params->cdrt->idx));
		extack->cookie_len = sizeof(xfrm_params->cdrt->idx);
	}

	spin_lock_bh(&xfrm_params_list.lock);
	list_add_tail(&xfrm_params->node, &xfrm_params_list.list);
	spin_unlock_bh(&xfrm_params_list.lock);

	return 0;

err_free:
	kfree(xfrm_params);
err_put_module:
	module_put(THIS_MODULE);

	return ret;
}

void mtk_xfrm_offload_state_delete(struct net_device *dev, struct xfrm_state *xs)
{
}

void mtk_xfrm_offload_state_free(struct net_device *dev, struct xfrm_state *xs)
{
	struct mtk_xfrm_params *xfrm_params;

	if (!xs->xso.offload_handle)
		return;

	xfrm_params = (struct mtk_xfrm_params *)xs->xso.offload_handle;
	xs->xso.offload_handle = 0;

	spin_lock_bh(&xfrm_params_list.lock);
	list_del(&xfrm_params->node);
	spin_unlock_bh(&xfrm_params_list.lock);

	if (xs->xso.dir == XFRM_DEV_OFFLOAD_IN)
		mtk_xfrm_offload_cls_entry_tear_down(xfrm_params);

	mtk_xfrm_offload_context_tear_down(xfrm_params);

	if (xfrm_params->cdrt)
		mtk_pce_cdrt_entry_free(xfrm_params->cdrt);

	kfree(xfrm_params);

	module_put(THIS_MODULE);
}

int mtk_xfrm_offload_policy_add(struct xfrm_policy *xp, struct netlink_ext_ack *extack)
{
	struct mtk_xfrm_params *xfrm_params;
	struct xfrm_state *xs;
	struct xfrm_tmpl *xt;

	if (xp->xfrm_nr < 1)
		return 0;

	xt = &xp->xfrm_vec[0];
	if (!xt->id.spi)
		return 0;

	xs = xfrm_state_lookup_byspi(&init_net, xt->id.spi, xt->encap_family);
	if (!xs)
		return 0;

	xfrm_params = (struct mtk_xfrm_params *)xs->xso.offload_handle;
	if (xfrm_params)
		xp->xdo.offload_handle = (unsigned long)xfrm_params;
	xfrm_state_put(xs);

	return 0;
}

static void mtk_xfrm_teardown_flows(struct work_struct *work)
{
	struct mtk_xfrm_teardown_work *tw =
		container_of(work, struct mtk_xfrm_teardown_work, work);

	mtk_flow_offload_teardown_by_tnl(mcrypto.eth, MTK_FOE_CRYPTO_DEL,
					 tw->cdrt_idx,
					 flow_offload_teardown_by_tuple);
	kfree(tw);
}

void mtk_xfrm_offload_policy_delete(struct xfrm_policy *xp)
{
	struct mtk_xfrm_params *xfrm_params;
	struct mtk_xfrm_teardown_work *tw;

	if (!xp->xdo.offload_handle)
		return;

	xfrm_params = (struct mtk_xfrm_params *)xp->xdo.offload_handle;
	xp->xdo.offload_handle = 0;

	if (!xfrm_params->cdrt)
		return;

	/* walking the PPE table can sleep and takes a while; this callback may
	 * run from the policy timer
	 */
	tw = kmalloc(sizeof(*tw), GFP_ATOMIC);
	if (!tw)
		return;

	INIT_WORK(&tw->work, mtk_xfrm_teardown_flows);
	tw->cdrt_idx = xfrm_params->cdrt->idx;
	queue_work(mtk_xfrm_wq, &tw->work);
}

void mtk_xfrm_offload_policy_free(struct xfrm_policy *xp)
{
}

/* Make the neighbour of @addr on @dev resolve without sending any packet:
 * the packet that triggered it is refused (it would be sent in clear text if
 * it were queued on the neighbour).
 */
static struct neighbour *mtk_crypto_find_ipv4_dst_mac(struct sk_buff *skb,
						      struct xfrm_state *xs)
{
	struct dst_entry *dst = xfrm_dst_path(skb_dst(skb));
	struct rtable *rt = (struct rtable *)dst;
	struct neighbour *neigh;
	__be32 nexthop;

	if (!netif_carrier_ok(dst->dev) || !(dst->dev->flags & IFF_UP))
		return NULL;

	/* nexthop from the routing table, then its MAC address */
	nexthop = rt_nexthop(rt, xs->id.daddr.a4);
	neigh = __ipv4_neigh_lookup_noref(dst->dev, nexthop);
	if (unlikely(!neigh)) {
		neigh = __neigh_create(&arp_tbl, &nexthop, dst->dev, false);
		if (!IS_ERR(neigh))
			neigh_event_send(neigh, NULL);
		return NULL;
	}

	/* nexthop has no MAC, arp may have failed on that IP: try the tunnel
	 * destination
	 */
	if (is_zero_ether_addr(neigh->ha)) {
		neigh = __ipv4_neigh_lookup_noref(dst->dev, xs->id.daddr.a4);
		if (unlikely(!neigh)) {
			neigh = __neigh_create(&arp_tbl, &xs->id.daddr.a4, dst->dev, false);
			if (!IS_ERR(neigh))
				neigh_event_send(neigh, NULL);
			return NULL;
		}
	}

	if (is_zero_ether_addr(neigh->ha)) {
		neigh_event_send(neigh, NULL);
		return NULL;
	}

	return neigh;
}

#if IS_BUILTIN(CONFIG_IPV6)
static struct neighbour *mtk_crypto_find_ipv6_dst_mac(struct sk_buff *skb,
						      struct xfrm_state *xs)
{
	struct dst_entry *dst = xfrm_dst_path(skb_dst(skb));
	struct rt6_info *rt = (struct rt6_info *)dst;
	struct neighbour *neigh;
	const struct in6_addr *nexthop;

	if (!netif_carrier_ok(dst->dev) || !(dst->dev->flags & IFF_UP))
		return NULL;

	nexthop = rt6_nexthop(rt, (struct in6_addr *)&xs->id.daddr.a6);
	neigh = __ipv6_neigh_lookup_noref(dst->dev, nexthop);
	if (unlikely(!neigh)) {
		neigh = __neigh_create(&nd_tbl, nexthop, dst->dev, false);
		if (!IS_ERR(neigh))
			neigh_event_send(neigh, NULL);
		return NULL;
	}

	if (is_zero_ether_addr(neigh->ha)) {
		neigh = __ipv6_neigh_lookup_noref(dst->dev, &xs->id.daddr.a6);
		if (unlikely(!neigh)) {
			neigh = __neigh_create(&nd_tbl, &xs->id.daddr.a6, dst->dev, false);
			if (!IS_ERR(neigh))
				neigh_event_send(neigh, NULL);
			return NULL;
		}
	}

	if (is_zero_ether_addr(neigh->ha)) {
		neigh_event_send(neigh, NULL);
		return NULL;
	}

	return neigh;
}
#endif

/* Called by xfrm_dev_offload_ok() for every packet of an offloaded state.
 * Returning false drops the packet (xfrm_output() never falls back to
 * software for packet offload), so every failure here fails closed.
 *
 * On success the Ethernet header is written into the headroom right in front
 * of the packet: xfrm_dev_direct_output() (tunnel mode) pushes
 * hard_header_len bytes there before it hands the packet to the device, the
 * other paths build their own header by neighbour output.
 */
bool mtk_xfrm_offload_ok(struct sk_buff *skb, struct xfrm_state *xs)
{
	struct mtk_xfrm_params *xfrm_params;
	struct dst_entry *dst = skb_dst(skb);
	struct net_device *dev;
	struct neighbour *neigh;

	xfrm_params = (struct mtk_xfrm_params *)xs->xso.offload_handle;
	if (!xfrm_params || !xfrm_params->cdrt || !dst)
		return false;

	dev = xfrm_dst_path(dst)->dev;
	if (!mtk_crypto_dev_supported(dev) || dev->type != ARPHRD_ETHER)
		return false;

	/* room for the Ethernet header and the tunnel descriptor */
	if (skb_cow_head(skb, ETH_HLEN + NET_SKB_PAD + NET_IP_ALIGN))
		return false;

	rcu_read_lock_bh();

	if (xs->props.family == AF_INET) {
		neigh = mtk_crypto_find_ipv4_dst_mac(skb, xs);
	} else {
#if IS_BUILTIN(CONFIG_IPV6)
		neigh = mtk_crypto_find_ipv6_dst_mac(skb, xs);
#else
		neigh = NULL;
#endif
	}
	if (!neigh) {
		rcu_read_unlock_bh();
		return false;
	}

	skb_push(skb, ETH_HLEN);
	memcpy(skb->data, neigh->ha, ETH_ALEN);
	memcpy(skb->data + ETH_ALEN, dev->dev_addr, ETH_ALEN);
	((struct ethhdr *)skb->data)->h_proto =
		htons(xs->props.family == AF_INET ? ETH_P_IP : ETH_P_IPV6);
	skb_pull(skb, ETH_HLEN);

	rcu_read_unlock_bh();

	/* tell mtk_eth_soc to send this packet through the EIP-197 */
	skb_tnl_cdrt(skb) = xfrm_params->cdrt->idx;
	skb_tnl_magic_tag(skb) = TNL_MAGIC_TAG;

	/* Segments and fragments do not inherit the headroom, so the hook in
	 * mtk_eth_soc only trusts packets that carry this protocol marker.
	 */
	skb->inner_protocol = IPPROTO_ESP;

	atomic64_add(skb->len, &xfrm_params->bytes);
	atomic64_inc(&xfrm_params->packets);

	return true;
}

int mtk_xfrm_offload_init(void)
{
	mtk_xfrm_wq = alloc_workqueue("mtk_crypto_xfrm", WQ_UNBOUND, 1);
	if (!mtk_xfrm_wq)
		return -ENOMEM;

	return 0;
}

void mtk_xfrm_offload_exit(void)
{
	if (mtk_xfrm_wq) {
		destroy_workqueue(mtk_xfrm_wq);
		mtk_xfrm_wq = NULL;
	}
}
