// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2024 MediaTek Inc.
 *
 * Author: Frank-zj Lin <frank-zj.lin@mediatek.com>
 */

#include <linux/debugfs.h>
#include <linux/netdevice.h>
#include <linux/rtnetlink.h>
#include <linux/seq_file.h>
#include <linux/spinlock.h>

#include <pce/cdrt.h>

#include "crypto-eip/crypto-eip.h"
#include "crypto-eip/debugfs.h"

static struct dentry *mtk_crypto_debugfs_root;
int mac_filter_enable;

static int mtk_crypto_xfrm_params_show(struct seq_file *s, void *private)
{
	struct xfrm_params_list *xfrm_params_list;
	struct mtk_xfrm_params *xfrm_params;

	xfrm_params_list = mtk_xfrm_params_list_get();

	spin_lock_bh(&xfrm_params_list->lock);

	list_for_each_entry(xfrm_params, &xfrm_params_list->list, node) {
		seq_printf(s, "XFRM STATE: spi 0x%x, cdrt_idx %3d: ",
			   be32_to_cpu(xfrm_params->xs->id.spi),
			   xfrm_params->cdrt->idx);

		if (xfrm_params->cdrt->type == CDRT_DECRYPT)
			seq_puts(s, "INBOUND\n");
		else if (xfrm_params->cdrt->type == CDRT_ENCRYPT)
			seq_puts(s, "OUTBOUND\n");
		else
			seq_puts(s, "\n");

		seq_printf(s, "\tBytes: %llu\n", atomic64_read(&xfrm_params->bytes));
		seq_printf(s, "\tPackets: %llu\n", atomic64_read(&xfrm_params->packets));
	}

	spin_unlock_bh(&xfrm_params_list->lock);

	return 0;
}
DEFINE_SHOW_ATTRIBUTE(mtk_crypto_xfrm_params);

/* write a netdev name to enable inline IPsec on a device that was created
 * after this module was loaded (only MediaTek ethernet devices are accepted)
 */
static ssize_t mtk_crypto_offload_dev_write(struct file *file,
					    const char __user *ubuf,
					    size_t count, loff_t *ppos)
{
	char buf[IFNAMSIZ] = {};
	struct net_device *dev;
	char *name, *tmp;

	if (count >= IFNAMSIZ)
		return -EINVAL;

	if (copy_from_user(buf, ubuf, count))
		return -EFAULT;

	tmp = buf;
	name = strsep(&tmp, "\n\r ");

	dev = dev_get_by_name(&init_net, name);
	if (!dev)
		return -ENODEV;

	if (!mtk_crypto_dev_supported(dev)) {
		dev_put(dev);
		return -EOPNOTSUPP;
	}

	rtnl_lock();
	mtk_crypto_enable_ipsec_dev_features(dev);
	rtnl_unlock();
	dev_put(dev);

	return count;
}

static const struct file_operations mtk_crypto_offload_dev_fops = {
	.open = simple_open,
	.write = mtk_crypto_offload_dev_write,
	.llseek = noop_llseek,
};

static int mtk_crypto_mac_filter_show(struct seq_file *m, void *private)
{
	seq_printf(m, "%d\n", mac_filter_enable);

	return 0;
}

static int mtk_crypto_mac_filter_open(struct inode *inode, struct file *file)
{
	return single_open(file, mtk_crypto_mac_filter_show, NULL);
}

/* decides where the PCE sends decrypted packets of states created afterwards */
static ssize_t mtk_crypto_mac_filter_write(struct file *file,
					   const char __user *buffer,
					   size_t count, loff_t *data)
{
	char buf[8] = {};

	if (count >= sizeof(buf))
		return -EINVAL;

	if (copy_from_user(buf, buffer, count))
		return -EFAULT;

	if (buf[0] == '1')
		mac_filter_enable = 1;
	else if (buf[0] == '0')
		mac_filter_enable = 0;
	else
		return -EINVAL;

	return count;
}

static const struct file_operations mtk_crypto_mac_filter_fops = {
	.open = mtk_crypto_mac_filter_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.write = mtk_crypto_mac_filter_write,
	.release = single_release,
};

int mtk_crypto_debugfs_init(void)
{
	mtk_crypto_debugfs_root = debugfs_create_dir("mtk_crypto", NULL);

	debugfs_create_file("xfrm_params", 0444, mtk_crypto_debugfs_root, NULL,
			    &mtk_crypto_xfrm_params_fops);
	debugfs_create_file("offload_dev", 0200, mtk_crypto_debugfs_root, NULL,
			    &mtk_crypto_offload_dev_fops);
	debugfs_create_file("mac_filter_enable", 0644, mtk_crypto_debugfs_root, NULL,
			    &mtk_crypto_mac_filter_fops);

	return 0;
}

void mtk_crypto_debugfs_exit(void)
{
	debugfs_remove_recursive(mtk_crypto_debugfs_root);
	mtk_crypto_debugfs_root = NULL;
}
