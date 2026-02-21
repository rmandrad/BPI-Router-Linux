// SPDX-License-Identifier: GPL-2.0-only
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/netlink.h>
#include <linux/netfilter.h>
#include <linux/spinlock.h>
#include <linux/if_vlan.h>
#include <linux/netfilter_bridge.h>
#include <linux/netfilter/nf_conntrack_common.h>
#include <linux/netfilter/nf_tables.h>
#include <net/ip.h>
#include <net/inet_dscp.h>
#include <net/netfilter/nf_tables.h>
#include <net/netfilter/nf_tables_core.h>
#include <net/netfilter/nf_conntrack_core.h>
#include <net/netfilter/nf_conntrack_extend.h>
#include <net/netfilter/nf_flow_table.h>
#include "../bridge/br_private.h"

static enum flow_offload_xmit_type nft_xmit_type(struct dst_entry *dst)
{
	if (dst_xfrm(dst))
		return FLOW_OFFLOAD_XMIT_XFRM;

	return FLOW_OFFLOAD_XMIT_NEIGH;
}

static void nft_default_forward_path(struct nf_flow_route *route,
				     struct dst_entry *dst_cache,
				     enum ip_conntrack_dir dir)
{
	route->tuple[!dir].in.ifindex	= dst_cache->dev->ifindex;
	route->tuple[dir].dst		= dst_cache;
	route->tuple[dir].xmit_type	= nft_xmit_type(dst_cache);
}

static bool nft_is_valid_ether_device(const struct net_device *dev)
{
	if (!dev || (dev->flags & IFF_LOOPBACK) || dev->type != ARPHRD_ETHER ||
	    dev->addr_len != ETH_ALEN || !is_valid_ether_addr(dev->dev_addr))
		return false;

	return true;
}

static u16 nft_flow_offload_get_vlan_id(struct net_bridge_port *port,
					struct sk_buff *skb)
{
	u16 vlan_id = 0;

	if (!port || !br_opt_get(port->br, BROPT_VLAN_ENABLED))
		return 0;

	if (skb_vlan_tag_present(skb))
		vlan_id = skb_vlan_tag_get_id(skb);
	else
		br_vlan_get_pvid_rcu(skb->dev, &vlan_id);

	return vlan_id;
}

static bool nft_flow_offload_is_bridging(struct sk_buff *skb)
{
	if (!netif_is_bridge_port(skb->dev) || !skb_mac_header_was_set(skb))
		return false;

#if IS_ENABLED(CONFIG_BRIDGE_NETFILTER)
	/* Bridge-forwarded packets have BR NF metadata with physout populated. */
	return nf_bridge_get_physoutif(skb) != 0;
#else
	return false;
#endif
}

static struct net_device_path *nft_dev_fwd_path(struct net_device_path_stack *stack)
{
	int k = stack->num_paths++;

	if (WARN_ON_ONCE(k >= NET_DEVICE_PATH_STACK_MAX))
		return NULL;

	return &stack->path[k];
}

static int nft_dev_fill_forward_path_ctx(struct net_device_path_ctx *ctx,
					 const u8 *daddr,
					 struct net_device_path_stack *stack)
{
	const struct net_device *last_dev;
	struct net_device_path *path;
	int ret = 0;

	memcpy(ctx->daddr, daddr, ETH_ALEN);
	stack->num_paths = 0;

	while (ctx->dev && ctx->dev->netdev_ops->ndo_fill_forward_path) {
		last_dev = ctx->dev;
		path = nft_dev_fwd_path(stack);
		if (!path)
			return -1;

		memset(path, 0, sizeof(*path));
		ret = ctx->dev->netdev_ops->ndo_fill_forward_path(ctx, path);
		if (ret < 0)
			return -1;

		if (WARN_ON_ONCE(last_dev == ctx->dev))
			return -1;
	}

	if (!ctx->dev)
		return ret;

	path = nft_dev_fwd_path(stack);
	if (!path)
		return -1;

	path->type = DEV_PATH_ETHERNET;
	path->dev = ctx->dev;

	return ret;
}

static int nft_dev_fill_forward_path(struct net_device_path_ctx *ctx,
				     const struct dst_entry *dst_cache,
				     const struct nf_conn *ct,
				     enum ip_conntrack_dir dir, u8 *ha,
				     struct net_device_path_stack *stack)
{
	const void *daddr = &ct->tuplehash[!dir].tuple.src.u3;
	struct net_device *dev = dst_cache->dev;
	struct neighbour *n;
	u8 nud_state;

	if (!nft_is_valid_ether_device(dev))
		goto out;

	if (is_zero_ether_addr(ha)) {
		n = dst_neigh_lookup(dst_cache, daddr);
		if (!n)
			return -1;

		read_lock_bh(&n->lock);
		nud_state = n->nud_state;
		ether_addr_copy(ha, n->ha);
		read_unlock_bh(&n->lock);
		neigh_release(n);

		if (!(nud_state & NUD_VALID))
			return -1;
	}

out:
	return nft_dev_fill_forward_path_ctx(ctx, ha, stack);
}

static void nft_br_vlan_dev_fill_forward_path(const struct nft_pktinfo *pkt,
					      struct net_device_path_ctx *ctx)
{
	struct net_bridge_port *port;
	u16 vlan_id;

	rcu_read_lock();
	port = br_port_get_rcu(pkt->skb->dev);
	if (port) {
		vlan_id = nft_flow_offload_get_vlan_id(port, pkt->skb);
		if (vlan_id) {
			ctx->num_vlans = 1;
			ctx->vlan[0].id = vlan_id;
			ctx->vlan[0].proto = port->br->vlan_proto;
		}
	}
	rcu_read_unlock();
}

struct nft_forward_info {
	const struct net_device *indev;
	const struct net_device *outdev;
	struct id {
		__u16	id;
		__be16	proto;
	} encap[NF_FLOW_TABLE_ENCAP_MAX];
	u8 num_encaps;
	struct flow_offload_tunnel tun;
	u8 num_tuns;
	u8 ingress_vlans;
	u8 h_source[ETH_ALEN];
	u8 h_dest[ETH_ALEN];
	u32 priority;
	enum flow_offload_xmit_type xmit_type;
};

static void nft_fill_vlan_passthrough_info(const struct nft_pktinfo *pkt,
					   struct nft_forward_info *info)
{
	struct net_bridge_port *port;

	if (!skb_vlan_tag_present(pkt->skb))
		return;

	rcu_read_lock();
	port = br_port_get_rcu(pkt->skb->dev);
	/* Bridge handles this VLAN when filtering is enabled on the bridge. */
	if (port && !br_opt_get(port->br, BROPT_VLAN_ENABLED)) {
		if (info->num_encaps >= NF_FLOW_TABLE_ENCAP_MAX) {
			info->indev = NULL;
			goto out;
		}

		info->encap[info->num_encaps].id = skb_vlan_tag_get_id(pkt->skb);
		info->encap[info->num_encaps].proto = pkt->skb->vlan_proto;
		info->num_encaps++;
	}

out:
	rcu_read_unlock();
}

static u16 nft_vlan_get_egress_qos(const struct net_device *dev, u32 priority)
{
	return vlan_dev_get_egress_qos_mask((struct net_device *)dev, priority);
}

static void nft_dev_path_info(const struct net_device_path_stack *stack,
			      struct nft_forward_info *info,
			      unsigned char *ha, struct nf_flowtable *flowtable)
{
	const struct net_device_path *path;
	u32 vlan_pcp;
	int i;

	memcpy(info->h_dest, ha, ETH_ALEN);

	for (i = 0; i < stack->num_paths; i++) {
		path = &stack->path[i];
		info->indev = path->dev;
		switch (path->type) {
		case DEV_PATH_ETHERNET:
		case DEV_PATH_DSA:
		case DEV_PATH_VLAN:
		case DEV_PATH_PPPOE:
		case DEV_PATH_TUN:
			if (is_zero_ether_addr(info->h_source))
				memcpy(info->h_source, path->dev->dev_addr, ETH_ALEN);

			if (path->type == DEV_PATH_ETHERNET)
				break;
			if (path->type == DEV_PATH_DSA) {
				i = stack->num_paths;
				break;
			}

			/* DEV_PATH_VLAN, DEV_PATH_PPPOE and DEV_PATH_TUN */
			if (path->type == DEV_PATH_TUN) {
				if (info->num_tuns) {
					info->indev = NULL;
					break;
				}
				info->tun.src_v6 = path->tun.src_v6;
				info->tun.dst_v6 = path->tun.dst_v6;
				info->tun.l3_proto = path->tun.l3_proto;
				info->num_tuns++;
			} else {
				if (info->num_encaps >= NF_FLOW_TABLE_ENCAP_MAX) {
					info->indev = NULL;
					break;
				}

				info->encap[info->num_encaps].id = path->encap.id;
				info->encap[info->num_encaps].proto = path->encap.proto;
				if (path->type == DEV_PATH_VLAN) {
					vlan_pcp = nft_vlan_get_egress_qos(path->dev,
									   info->priority);
					info->encap[info->num_encaps].id |= vlan_pcp;
				}

				info->num_encaps++;
			}

			if (path->type == DEV_PATH_PPPOE)
				memcpy(info->h_dest, path->encap.h_dest, ETH_ALEN);
			break;
		case DEV_PATH_BRIDGE:
			if (is_zero_ether_addr(info->h_source))
				memcpy(info->h_source, path->dev->dev_addr, ETH_ALEN);

			switch (path->bridge.vlan_mode) {
			case DEV_PATH_BR_VLAN_UNTAG_HW:
				info->ingress_vlans |= BIT(info->num_encaps - 1);
				break;
			case DEV_PATH_BR_VLAN_TAG:
				if (info->num_encaps >= NF_FLOW_TABLE_ENCAP_MAX) {
					info->indev = NULL;
					break;
				}
				info->encap[info->num_encaps].id = path->bridge.vlan_id;
				info->encap[info->num_encaps].proto = path->bridge.vlan_proto;
				info->num_encaps++;
				break;
			case DEV_PATH_BR_VLAN_UNTAG:
				if (info->num_encaps > 0) {
					info->num_encaps--;
					if (WARN_ON_ONCE(info->num_encaps == 0)) {
						info->indev = NULL;
						break;
					}
				}
				break;
			case DEV_PATH_BR_VLAN_KEEP:
				break;
			}
			info->xmit_type = FLOW_OFFLOAD_XMIT_DIRECT;
			break;
		case DEV_PATH_MTK_WDMA:
			if (is_zero_ether_addr(info->h_source))
				memcpy(info->h_source, path->dev->dev_addr, ETH_ALEN);
			break;
		default:
			break;
		}
	}
	info->outdev = info->indev;

	if (nf_flowtable_hw_offload(flowtable) &&
	    nft_is_valid_ether_device(info->indev))
		info->xmit_type = FLOW_OFFLOAD_XMIT_DIRECT;
}

static bool nft_flowtable_find_dev(const struct net_device *dev,
				   struct nft_flowtable *ft)
{
	struct nft_hook *hook;
	bool found = false;

	list_for_each_entry_rcu(hook, &ft->hook_list, list) {
		if (!nft_hook_find_ops_rcu(hook, dev))
			continue;

		found = true;
		break;
	}

	return found;
}

static int nft_flow_tunnel_update_route(const struct nft_pktinfo *pkt,
					struct flow_offload_tunnel *tun,
					struct nf_flow_route *route,
					enum ip_conntrack_dir dir)
{
	struct dst_entry *cur_dst = route->tuple[dir].dst;
	struct dst_entry *tun_dst = NULL;
	struct flowi fl = {};

	switch (nft_pf(pkt)) {
	case NFPROTO_IPV4:
		fl.u.ip4.daddr = tun->dst_v4.s_addr;
		fl.u.ip4.saddr = tun->src_v4.s_addr;
		fl.u.ip4.flowi4_iif = nft_in(pkt)->ifindex;
		fl.u.ip4.flowi4_dscp = ip4h_dscp(ip_hdr(pkt->skb));
		fl.u.ip4.flowi4_mark = pkt->skb->mark;
		fl.u.ip4.flowi4_flags = FLOWI_FLAG_ANYSRC;
		break;
	case NFPROTO_IPV6:
		fl.u.ip6.daddr = tun->dst_v6;
		fl.u.ip6.saddr = tun->src_v6;
		fl.u.ip6.flowi6_iif = nft_in(pkt)->ifindex;
		fl.u.ip6.flowlabel = ip6_flowinfo(ipv6_hdr(pkt->skb));
		fl.u.ip6.flowi6_mark = pkt->skb->mark;
		fl.u.ip6.flowi6_flags = FLOWI_FLAG_ANYSRC;
		break;
	}

	nf_route(nft_net(pkt), &tun_dst, &fl, false, nft_pf(pkt));
	if (!tun_dst)
		return -ENOENT;

	route->tuple[dir].dst = tun_dst;
	dst_release(cur_dst);

	return 0;
}

static int nft_dev_forward_path(const struct nft_pktinfo *pkt,
				struct nf_flow_route *route,
				const struct nf_conn *ct,
				enum ip_conntrack_dir dir,
				struct nft_flowtable *ft)
{
	const struct dst_entry *dst = route->tuple[dir].dst;
	struct net_device_path_ctx ctx = {
		.dev = dst->dev,
	};
	struct net_device_path_stack stack;
	struct nft_forward_info info = {
		.priority = pkt->skb->priority,
	};
	struct ethhdr *eth;
	enum ip_conntrack_dir skb_dir;
	unsigned char ha[ETH_ALEN];
	int i;

	memset(ha, 0, sizeof(ha));

	if (nft_flow_offload_is_bridging(pkt->skb) && skb_mac_header_was_set(pkt->skb)) {
		eth = eth_hdr(pkt->skb);
		skb_dir = CTINFO2DIR(skb_get_nfct(pkt->skb) & NFCT_INFOMASK);
		if (skb_dir != dir) {
			memcpy(ha, eth->h_source, ETH_ALEN);
			memcpy(info.h_source, eth->h_dest, ETH_ALEN);
		} else {
			memcpy(ha, eth->h_dest, ETH_ALEN);
			memcpy(info.h_source, eth->h_source, ETH_ALEN);
		}

		nft_br_vlan_dev_fill_forward_path(pkt, &ctx);
	}

	if (nft_dev_fill_forward_path(&ctx, dst, ct, dir, ha, &stack) >= 0) {
		nft_fill_vlan_passthrough_info(pkt, &info);
		nft_dev_path_info(&stack, &info, ha, &ft->data);
	}

	if (info.outdev)
		route->tuple[dir].out.ifindex = info.outdev->ifindex;

	if (!info.indev || !nft_flowtable_find_dev(info.indev, ft))
		return -ENOENT;

	route->tuple[!dir].in.ifindex = info.indev->ifindex;
	for (i = 0; i < info.num_encaps; i++) {
		route->tuple[!dir].in.encap[i].id = info.encap[i].id;
		route->tuple[!dir].in.encap[i].proto = info.encap[i].proto;
	}

	if (info.num_tuns &&
	    !nft_flow_tunnel_update_route(pkt, &info.tun, route, dir)) {
		route->tuple[!dir].in.tun.src_v6 = info.tun.dst_v6;
		route->tuple[!dir].in.tun.dst_v6 = info.tun.src_v6;
		route->tuple[!dir].in.tun.l3_proto = info.tun.l3_proto;
		route->tuple[!dir].in.num_tuns = info.num_tuns;
	}

	route->tuple[!dir].in.num_encaps = info.num_encaps;
	route->tuple[!dir].in.ingress_vlans = info.ingress_vlans;

	if (info.xmit_type == FLOW_OFFLOAD_XMIT_DIRECT &&
	    route->tuple[dir].xmit_type != FLOW_OFFLOAD_XMIT_XFRM) {
		memcpy(route->tuple[dir].out.h_source, info.h_source, ETH_ALEN);
		memcpy(route->tuple[dir].out.h_dest, info.h_dest, ETH_ALEN);
		route->tuple[dir].xmit_type = info.xmit_type;
	}

	return 0;
}

static int nft_flow_route_routing(const struct nft_pktinfo *pkt,
				  const struct nf_conn *ct,
				  struct nf_flow_route *route,
				  enum ip_conntrack_dir dir,
				  struct nft_flowtable *ft)
{
	struct dst_entry *this_dst = skb_dst(pkt->skb);
	struct dst_entry *other_dst = NULL;
	struct flowi fl;

	memset(&fl, 0, sizeof(fl));
	switch (nft_pf(pkt)) {
	case NFPROTO_IPV4:
		fl.u.ip4.daddr = ct->tuplehash[dir].tuple.src.u3.ip;
		fl.u.ip4.saddr = ct->tuplehash[!dir].tuple.src.u3.ip;
		fl.u.ip4.flowi4_oif = nft_in(pkt)->ifindex;
		fl.u.ip4.flowi4_iif = this_dst->dev->ifindex;
		fl.u.ip4.flowi4_dscp = ip4h_dscp(ip_hdr(pkt->skb));
		fl.u.ip4.flowi4_mark = pkt->skb->mark;
		fl.u.ip4.flowi4_flags = FLOWI_FLAG_ANYSRC;
		break;
	case NFPROTO_IPV6:
		fl.u.ip6.daddr = ct->tuplehash[dir].tuple.src.u3.in6;
		fl.u.ip6.saddr = ct->tuplehash[!dir].tuple.src.u3.in6;
		fl.u.ip6.flowi6_oif = nft_in(pkt)->ifindex;
		fl.u.ip6.flowi6_iif = this_dst->dev->ifindex;
		fl.u.ip6.flowlabel = ip6_flowinfo(ipv6_hdr(pkt->skb));
		fl.u.ip6.flowi6_mark = pkt->skb->mark;
		fl.u.ip6.flowi6_flags = FLOWI_FLAG_ANYSRC;
		break;
	}

	if (!dst_hold_safe(this_dst))
		return -ENOENT;

	nf_route(nft_net(pkt), &other_dst, &fl, false, nft_pf(pkt));
	if (!other_dst) {
		dst_release(this_dst);
		return -ENOENT;
	}

	nft_default_forward_path(route, this_dst, dir);
	nft_default_forward_path(route, other_dst, !dir);

	if (route->tuple[dir].xmit_type == FLOW_OFFLOAD_XMIT_NEIGH &&
	    route->tuple[!dir].xmit_type == FLOW_OFFLOAD_XMIT_NEIGH) {
		if (nft_dev_forward_path(pkt, route, ct, dir, ft) ||
		    nft_dev_forward_path(pkt, route, ct, !dir, ft)) {
			dst_release(route->tuple[dir].dst);
			dst_release(route->tuple[!dir].dst);
			return -ENOENT;
		}
	}

	return 0;
}

static int nft_flow_route_dir(const struct nft_pktinfo *pkt,
			      const struct nf_conn *ct,
			      struct nf_flow_route *route,
			      enum ip_conntrack_dir dir,
			      int ifindex)
{
	struct dst_entry *other_dst = NULL;
	struct flowi fl;

	memset(&fl, 0, sizeof(fl));
	switch (nft_pf(pkt)) {
	case NFPROTO_IPV4:
		fl.u.ip4.daddr = ct->tuplehash[!dir].tuple.src.u3.ip;
		fl.u.ip4.flowi4_oif = ifindex;
		fl.u.ip4.flowi4_dscp = ip4h_dscp(ip_hdr(pkt->skb));
		fl.u.ip4.flowi4_mark = pkt->skb->mark;
		fl.u.ip4.flowi4_flags = FLOWI_FLAG_ANYSRC;
		break;
	case NFPROTO_IPV6:
		fl.u.ip6.saddr = ct->tuplehash[!dir].tuple.dst.u3.in6;
		fl.u.ip6.daddr = ct->tuplehash[!dir].tuple.src.u3.in6;
		fl.u.ip6.flowi6_oif = ifindex;
		fl.u.ip6.flowlabel = ip6_flowinfo(ipv6_hdr(pkt->skb));
		fl.u.ip6.flowi6_mark = pkt->skb->mark;
		fl.u.ip6.flowi6_flags = FLOWI_FLAG_ANYSRC;
		break;
	}

	nf_route(nft_net(pkt), &other_dst, &fl, false, nft_pf(pkt));
	if (!other_dst)
		return -ENOENT;

	nft_default_forward_path(route, other_dst, dir);

	return 0;
}

static int nft_flow_route_bridging(const struct nft_pktinfo *pkt,
				   const struct nf_conn *ct,
				   struct nf_flow_route *route,
				   enum ip_conntrack_dir dir,
				   struct nft_flowtable *ft)
{
	int ret;

	ret = nft_flow_route_dir(pkt, ct, route, dir, nft_out(pkt)->ifindex);
	if (ret)
		return ret;

	ret = nft_flow_route_dir(pkt, ct, route, !dir, nft_in(pkt)->ifindex);
	if (ret)
		goto err_route_dir1;

	if (route->tuple[dir].xmit_type == FLOW_OFFLOAD_XMIT_NEIGH &&
	    route->tuple[!dir].xmit_type == FLOW_OFFLOAD_XMIT_NEIGH) {
		if (nft_dev_forward_path(pkt, route, ct, dir, ft) ||
		    nft_dev_forward_path(pkt, route, ct, !dir, ft)) {
			ret = -ENOENT;
			goto err_route_dir2;
		}
	}

	return 0;

err_route_dir2:
	dst_release(route->tuple[!dir].dst);
err_route_dir1:
	dst_release(route->tuple[dir].dst);
	return ret;
}

int nft_flow_route(const struct nft_pktinfo *pkt, const struct nf_conn *ct,
		   struct nf_flow_route *route, enum ip_conntrack_dir dir,
		   struct nft_flowtable *ft)
{
	if (nft_flow_offload_is_bridging(pkt->skb))
		return nft_flow_route_bridging(pkt, ct, route, dir, ft);

	return nft_flow_route_routing(pkt, ct, route, dir, ft);
}
EXPORT_SYMBOL_GPL(nft_flow_route);
