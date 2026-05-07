// SPDX-License-Identifier: ISC
/* Copyright (C) 2026 MediaTek Inc. */

#include <net/netlink.h>

#include "mt7996.h"
#include "mcu.h"
#include "vendor.h"

static const struct nla_policy
scs_ctrl_policy[NUM_MTK_VENDOR_ATTRS_SCS_CTRL] = {
	[MTK_VENDOR_ATTR_SCS_ID] = { .type = NLA_U8 },
	[MTK_VENDOR_ATTR_SCS_REQ_TYPE] = { .type = NLA_U8 },
	[MTK_VENDOR_ATTR_SCS_DIR] = { .type = NLA_U8 },
	[MTK_VENDOR_ATTR_SCS_QOS_IE] = { .type = NLA_BINARY },
	[MTK_VENDOR_ATTR_SCS_MAC_ADDR] = NLA_POLICY_ETH_ADDR,
	[MTK_VENDOR_ATTR_SCS_LINK_ID] = { .type = NLA_U8 },
};

static int
mt7996_vendor_scs_ctrl(struct wiphy *wiphy, struct wireless_dev *wdev,
		       const void *data, int data_len)
{
	struct ieee80211_hw *hw = wiphy_to_ieee80211_hw(wiphy);
	struct mt7996_dev *dev = mt7996_hw_dev(hw);
	struct mt7996_sta_link *link;
	struct mt7996_sta *msta;
	struct ieee80211_sta *sta;
	struct nlattr *tb[NUM_MTK_VENDOR_ATTRS_SCS_CTRL];
	u8 sta_addr[ETH_ALEN];
	u8 scs_id, req_type, dir = 0, link_id, qos_ie_len = 0;
	u8 *qos_ie = NULL;
	u16 wlan_idx;
	int err;

	err = nla_parse(tb, MTK_VENDOR_ATTR_SCS_CTRL_MAX, data, data_len,
			scs_ctrl_policy, NULL);
	if (err)
		return err;

	if (!tb[MTK_VENDOR_ATTR_SCS_ID] ||
	    !tb[MTK_VENDOR_ATTR_SCS_REQ_TYPE] ||
	    !tb[MTK_VENDOR_ATTR_SCS_MAC_ADDR] ||
	    !tb[MTK_VENDOR_ATTR_SCS_LINK_ID])
		return -EINVAL;

	scs_id = nla_get_u8(tb[MTK_VENDOR_ATTR_SCS_ID]);
	req_type = nla_get_u8(tb[MTK_VENDOR_ATTR_SCS_REQ_TYPE]);
	link_id = nla_get_u8(tb[MTK_VENDOR_ATTR_SCS_LINK_ID]);
	nla_memcpy(sta_addr, tb[MTK_VENDOR_ATTR_SCS_MAC_ADDR], ETH_ALEN);

	if (req_type == SCS_REQ_TYPE_ADD || req_type == SCS_REQ_TYPE_CHANGE) {
		if (!tb[MTK_VENDOR_ATTR_SCS_DIR] ||
		    !tb[MTK_VENDOR_ATTR_SCS_QOS_IE])
			return -EINVAL;

		dir = nla_get_u8(tb[MTK_VENDOR_ATTR_SCS_DIR]);
		qos_ie_len = nla_len(tb[MTK_VENDOR_ATTR_SCS_QOS_IE]);
		qos_ie = kmemdup(nla_data(tb[MTK_VENDOR_ATTR_SCS_QOS_IE]),
				 qos_ie_len, GFP_KERNEL);
		if (!qos_ie)
			return -ENOMEM;
	}

	rcu_read_lock();
	sta = ieee80211_find_sta_by_ifaddr(hw, sta_addr, NULL);
	if (!sta) {
		rcu_read_unlock();
		err = -ENOENT;
		goto out;
	}

	msta = (struct mt7996_sta *)sta->drv_priv;
	if (link_id >= IEEE80211_MLD_MAX_NUM_LINKS ||
	    !(sta->valid_links & BIT(link_id)))
		link_id = msta->deflink_id;

	link = rcu_dereference(msta->link[link_id]);
	if (!link) {
		rcu_read_unlock();
		err = -ENOENT;
		goto out;
	}

	wlan_idx = link->wcid.idx;
	rcu_read_unlock();

	err = mt7996_mcu_set_muru_qos_cfg(dev, wlan_idx, dir, scs_id,
					  req_type, qos_ie, qos_ie_len);

out:
	kfree(qos_ie);

	return err;
}

static const struct wiphy_vendor_command mt7996_vendor_commands[] = {
	{
		.info = {
			.vendor_id = MTK_NL80211_VENDOR_ID,
			.subcmd = MTK_NL80211_VENDOR_SUBCMD_SCS_CTRL,
		},
		.flags = WIPHY_VENDOR_CMD_NEED_NETDEV |
			 WIPHY_VENDOR_CMD_NEED_RUNNING,
		.doit = mt7996_vendor_scs_ctrl,
		.policy = scs_ctrl_policy,
		.maxattr = MTK_VENDOR_ATTR_SCS_CTRL_MAX,
	},
};

void mt7996_vendor_register(struct mt7996_phy *phy)
{
	struct wiphy *wiphy = phy->mt76->hw->wiphy;

	wiphy->vendor_commands = mt7996_vendor_commands;
	wiphy->n_vendor_commands = ARRAY_SIZE(mt7996_vendor_commands);
}
