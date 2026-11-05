// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2023 MediaTek Inc.
 *
 * Author: Chris.Chou <chris.chou@mediatek.com>
 *         Ren-Ting Wang <ren-ting.wang@mediatek.com>
 */

#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/of.h>
#include <linux/of_platform.h>
#include <linux/platform_device.h>
#include <linux/rtnetlink.h>
#include <net/dsa.h>

#include <mtk_eth_soc.h>
#include <mtk_ppe.h>
#include <mtk_tnl.h>

#include <pce/netsys.h>

#include "crypto-eip/crypto-eip.h"
#include "crypto-eip/ddk-wrapper.h"
#include "crypto-eip/debugfs.h"
#include "crypto-eip/internal.h"

#define DRIVER_AUTHOR	"Ren-Ting Wang <ren-ting.wang@mediatek.com>, " \
			"Chris.Chou <chris.chou@mediatek.com>"

struct mtk_crypto mcrypto;
struct device *crypto_dev;

static struct platform_device *crypto_pdev;

static inline void crypto_eip_write(u32 reg, u32 val)
{
	writel(val, mcrypto.crypto_base + reg);
}

/* Which PPE the packets of @dev are processed by (decides where the PCE sends
 * the decrypted packets).
 */
u32 mtk_crypto_ppe_get_num(struct net_device *dev)
{
	struct mtk_mac *mac;

	if (mcrypto.ppe_num == 1)
		return PSE_PORT_PPE0;

#if IS_ENABLED(CONFIG_NET_DSA)
	if (dsa_user_dev_check(dev)) {
		struct dsa_port *dp = dsa_port_from_netdev(dev);

		if (IS_ERR(dp) || !dp->cpu_dp)
			return PSE_PORT_PPE0;

		dev = dp->cpu_dp->conduit;
	}
#endif

	mac = netdev_priv(dev);
	if (mac->id == MTK_GMAC2_ID)
		return PSE_PORT_PPE1;
	else if (mac->id == MTK_GMAC3_ID)
		return PSE_PORT_PPE2;

	return PSE_PORT_PPE0;
}

static const struct xfrmdev_ops mtk_xfrmdev_ops = {
	.xdo_dev_state_add	= mtk_xfrm_offload_state_add,
	.xdo_dev_state_delete	= mtk_xfrm_offload_state_delete,
	.xdo_dev_state_free	= mtk_xfrm_offload_state_free,
	.xdo_dev_offload_ok	= mtk_xfrm_offload_ok,
	.xdo_dev_policy_add	= mtk_xfrm_offload_policy_add,
	.xdo_dev_policy_delete	= mtk_xfrm_offload_policy_delete,
	.xdo_dev_policy_free	= mtk_xfrm_offload_policy_free,
};

/* Only devices that really send through the MediaTek ethernet get HW_ESP:
 * a state on any other device would be sent on as plain text.
 */
void mtk_crypto_enable_ipsec_dev_features(struct net_device *dev)
{
	ASSERT_RTNL();

	if (!mtk_crypto_dev_supported(dev) || dev->xfrmdev_ops)
		return;

	dev->xfrmdev_ops = &mtk_xfrmdev_ops;
	dev->features |= NETIF_F_HW_ESP;
	dev->hw_enc_features |= NETIF_F_HW_ESP;

	netdev_change_features(dev);

	if (dev->features & NETIF_F_HW_ESP)
		CRYPTO_INFO("dev: %s, enable hw offload ipsec success\n", dev->name);
	else
		CRYPTO_INFO("dev: %s, enable hw offload ipsec failed\n", dev->name);
}

void mtk_crypto_disable_ipsec_dev_features(struct net_device *dev)
{
	ASSERT_RTNL();

	if (dev->xfrmdev_ops != &mtk_xfrmdev_ops)
		return;

	dev->xfrmdev_ops = NULL;
	dev->features &= ~NETIF_F_HW_ESP;
	dev->hw_enc_features &= ~NETIF_F_HW_ESP;

	netdev_change_features(dev);
}

int mtk_crypto_enable_all_dev_features(void)
{
	struct net_device *dev;

	rtnl_lock();
	for_each_netdev(&init_net, dev)
		mtk_crypto_enable_ipsec_dev_features(dev);
	rtnl_unlock();

	return 0;
}

void mtk_crypto_disable_all_dev_features(void)
{
	struct net_device *dev;

	rtnl_lock();
	for_each_netdev(&init_net, dev)
		mtk_crypto_disable_ipsec_dev_features(dev);
	rtnl_unlock();
}

static void mtk_crypto_hooks_exit(void)
{
	WRITE_ONCE(mtk_crypto_set_dec_secpath, NULL);
	WRITE_ONCE(mtk_flow_offload_get_cdrt, NULL);
	WRITE_ONCE(mtk_gso_skb_copy_head, NULL);

	/* wait for in-flight RX NAPI and TX callers before module text goes away */
	synchronize_net();
}

static void mtk_crypto_hooks_init(void)
{
	WRITE_ONCE(mtk_flow_offload_get_cdrt, mtk_crypto_xfrm_get_cdrt);
	WRITE_ONCE(mtk_gso_skb_copy_head, mtk_skb_copy_head);
	WRITE_ONCE(mtk_crypto_set_dec_secpath, mtk_crypto_decrypt_sec_path_setup);
}

static int mtk_crypto_eip_dts_init(void)
{
	struct device_node *crypto_node, *eth_node;
	struct platform_device *eth_pdev;
	struct resource *res;
	int ret;

	crypto_node = of_find_compatible_node(NULL, NULL, HWPAL_PLATFORM_DEVICE_NAME);
	if (!crypto_node)
		return -ENODEV;

	crypto_pdev = of_find_device_by_node(crypto_node);
	if (!crypto_pdev) {
		ret = -ENODEV;
		goto out_node;
	}

	/* the DDK ksupport driver must be bound to the device */
	if (!crypto_pdev->dev.driver) {
		ret = -ENODEV;
		goto err_put_dev;
	}

	crypto_dev = &crypto_pdev->dev;

	res = platform_get_resource(crypto_pdev, IORESOURCE_MEM, 0);
	if (!res) {
		ret = -ENXIO;
		goto err_put_dev;
	}

	/* the DDK driver owns the region, only map it */
	mcrypto.crypto_base = ioremap(res->start, resource_size(res));
	if (!mcrypto.crypto_base) {
		ret = -ENOMEM;
		goto err_put_dev;
	}

	eth_node = of_parse_phandle(crypto_node, "eth", 0);
	if (!eth_node) {
		ret = -ENODEV;
		goto err_unmap;
	}

	eth_pdev = of_find_device_by_node(eth_node);
	of_node_put(eth_node);
	if (!eth_pdev) {
		ret = -ENODEV;
		goto err_unmap;
	}

	if (!eth_pdev->dev.driver) {
		put_device(&eth_pdev->dev);
		ret = -ENODEV;
		goto err_unmap;
	}

	/* mtk_eth_soc is built in, the pointer stays valid */
	mcrypto.eth = platform_get_drvdata(eth_pdev);
	put_device(&eth_pdev->dev);
	if (!mcrypto.eth) {
		ret = -ENODEV;
		goto err_unmap;
	}

	mcrypto.ppe_num = mcrypto.eth->soc->ppe_num;

	of_node_put(crypto_node);

	return 0;

err_unmap:
	iounmap(mcrypto.crypto_base);
	mcrypto.crypto_base = NULL;
err_put_dev:
	put_device(&crypto_pdev->dev);
	crypto_pdev = NULL;
	crypto_dev = NULL;
out_node:
	of_node_put(crypto_node);

	return ret;
}

static void mtk_crypto_eip_dts_exit(void)
{
	iounmap(mcrypto.crypto_base);
	mcrypto.crypto_base = NULL;
	mcrypto.eth = NULL;

	put_device(&crypto_pdev->dev);
	crypto_pdev = NULL;
	crypto_dev = NULL;
}

static int mtk_crypto_eip_hw_init(void)
{
	crypto_eip_write(EIP197_FORCE_CLK_ON, 0xffffffff);
	crypto_eip_write(EIP197_FORCE_CLK_ON2, 0xffffffff);

	return mtk_ddk_pec_init();
}

static void mtk_crypto_eip_hw_deinit(void)
{
	mtk_ddk_pec_deinit();

	crypto_eip_write(EIP197_FORCE_CLK_ON, 0);
	crypto_eip_write(EIP197_FORCE_CLK_ON2, 0);
}

static int __init mtk_crypto_eip_init(void)
{
	int ret;

	ret = mtk_crypto_eip_dts_init();
	if (ret) {
		pr_err("crypto-eip: dts init failed: %d (are the DDK modules loaded?)\n", ret);
		return ret;
	}

	ret = mtk_xfrm_offload_init();
	if (ret)
		goto err_dts_exit;

	ret = mtk_crypto_eip_hw_init();
	if (ret) {
		CRYPTO_ERR("crypto-eip hw init failed: %d\n", ret);
		goto err_xfrm_exit;
	}

	ret = mtk_crypto_enable_all_dev_features();
	if (ret)
		goto err_hw_deinit;

	mtk_crypto_hooks_init();
	mtk_crypto_debugfs_init();

	CRYPTO_INFO("crypto-eip init done\n");

	return 0;

err_hw_deinit:
	mtk_crypto_eip_hw_deinit();
err_xfrm_exit:
	mtk_xfrm_offload_exit();
err_dts_exit:
	mtk_crypto_eip_dts_exit();

	return ret;
}

static void __exit mtk_crypto_eip_exit(void)
{
	/* no offloaded xfrm state can exist: each one holds a module reference */
	mtk_crypto_debugfs_exit();
	mtk_crypto_hooks_exit();
	mtk_crypto_disable_all_dev_features();
	mtk_xfrm_offload_exit();
	mtk_crypto_eip_hw_deinit();
	mtk_crypto_eip_dts_exit();
}

module_init(mtk_crypto_eip_init);
module_exit(mtk_crypto_eip_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("MediaTek Crypto EIP-197 inline IPsec offload driver");
MODULE_AUTHOR(DRIVER_AUTHOR);
