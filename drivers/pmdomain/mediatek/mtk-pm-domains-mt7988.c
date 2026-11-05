// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2025 MediaTek Inc.
 */
#include <linux/bits.h>
#include <linux/delay.h>
#include <linux/init.h>
#include <linux/io.h>
#include <linux/iopoll.h>
#include <linux/mfd/syscon.h>
#include <linux/mod_devicetable.h>
#include <linux/overflow.h>
#include <linux/platform_device.h>
#include <linux/pm_domain.h>
#include <linux/property.h>
#include <linux/regmap.h>

#include <dt-bindings/power/mt7988-power.h>

#include "mtk-pm-domains-mt7988.h"

#define MTK_POLL_DELAY_US 30
#define MTK_POLL_TIMEOUT  USEC_PER_SEC

struct scpsys_domain {
	const struct scpsys_domain_data *data;
	struct generic_pm_domain genpd;
	struct scpsys *scpsys;
};

struct scpsys {
	struct device *dev;
	struct regmap *base;
	const struct scpsys_soc_data *soc_data;
	struct genpd_onecell_data pd_data;
	struct generic_pm_domain *domains[];
};

/*
 * MT7988 power domain support
 */
static const struct scpsys_domain_data scpsys_domain_data_mt7988[] = {
	[MT7988_POWER_DOMAIN_TOPS0] = {
		.sta_mask = BIT(30),
		.sta_2nd_mask = BIT(31),
		.pwr_sta_offs = 0x040,
		.pwr_sta_2nd_offs = 0x040,
		.pwr_on_bit = BIT(1),
		.pwr_on_2nd_bit = BIT(2),
		.pwr_on_offs  = 0x040,
		.pwr_on_2nd_offs = 0x040,
		.pwr_clamp_bit = BIT(4),
		.pwr_rst_bit = BIT(0),
		.sram_pdn_bit = BIT(2),
		.sram_pdn_ack_bit = BIT(28),
		.sram_clk_iso_bit = BIT(0),
		.sram_ctrl_offs = 0x048,
		.sram_2nd_pdn_bit = BIT(8),
		.sram_2nd_pdn_ack_bit = BIT(24),
		.sram_2nd_clk_iso_bit = BIT(5),
		.sram_2nd_clk_dis_bit = BIT(3),
		.sram_2nd_ctrl_offs = 0x040,
		.caps = MTK_SCPD_KEEP_DEFAULT_OFF,
		.name = "power_domain_tops0",
	},
	[MT7988_POWER_DOMAIN_TOPS1] = {
		.sta_mask = BIT(30),
		.sta_2nd_mask = BIT(31),
		.pwr_sta_offs = 0x044,
		.pwr_sta_2nd_offs = 0x044,
		.pwr_on_bit = BIT(1),
		.pwr_on_2nd_bit = BIT(2),
		.pwr_on_offs  = 0x044,
		.pwr_on_2nd_offs = 0x044,
		.pwr_clamp_bit = BIT(4),
		.pwr_rst_bit = BIT(0),
		.sram_pdn_bit = BIT(6),
		.sram_pdn_ack_bit = BIT(30),
		.sram_clk_iso_bit = BIT(4),
		.sram_ctrl_offs = 0x048,
		.sram_2nd_pdn_bit = BIT(8),
		.sram_2nd_pdn_ack_bit = BIT(24),
		.sram_2nd_clk_iso_bit = BIT(5),
		.sram_2nd_clk_dis_bit = BIT(3),
		.sram_2nd_ctrl_offs = 0x044,
		.caps = MTK_SCPD_KEEP_DEFAULT_OFF,
		.name = "power_domain_tops1",
	},
};

static const struct scpsys_soc_data mt7988_scpsys_data = {
	.domains_data = scpsys_domain_data_mt7988,
	.num_domains = ARRAY_SIZE(scpsys_domain_data_mt7988),
};

static inline int mtk_regmap_set_bits(struct regmap *map, unsigned int reg, unsigned int bits)
{
	return regmap_update_bits_base(map, reg, bits, bits, NULL, false, false);
}

static inline int mtk_regmap_clear_bits(struct regmap *map, unsigned int reg, unsigned int bits)
{
	return regmap_update_bits_base(map, reg, bits, 0, NULL, false, false);
}

static bool scpsys_domain_is_on(struct scpsys_domain *pd)
{
	struct scpsys *scpsys = pd->scpsys;
	u32 status = 0, status2 = 0;

	regmap_read(scpsys->base, pd->data->pwr_sta_offs, &status);
	status &= pd->data->sta_mask;

	regmap_read(scpsys->base, pd->data->pwr_sta_2nd_offs, &status2);
	status2 &= pd->data->sta_2nd_mask;

	/* A domain is on when both status bits are set. */
	return status && status2;
}

static int scpsys_sram_enable(struct scpsys_domain *pd)
{
	struct scpsys *scpsys = pd->scpsys;
	u32 pdn_ack = pd->data->sram_pdn_ack_bit;
	u32 pdn_2nd_ack = pd->data->sram_2nd_pdn_ack_bit;
	u32 tmp = 0;
	int ret;

	if (pd->data->sram_pdn_bit) {
		mtk_regmap_clear_bits(scpsys->base, pd->data->sram_ctrl_offs,
				      pd->data->sram_pdn_bit);

		/* Either wait until SRAM_PDN_ACK all 1 or 0 */
		ret = regmap_read_poll_timeout(scpsys->base, pd->data->sram_ctrl_offs, tmp,
					       (tmp & pdn_ack) == 0, MTK_POLL_DELAY_US,
					       MTK_POLL_TIMEOUT);
		if (ret)
			return ret;
	}
	if (pd->data->sram_2nd_pdn_bit) {
		/* sram pdn 2nd for special mtcmos */
		mtk_regmap_clear_bits(scpsys->base, pd->data->sram_2nd_ctrl_offs,
				      pd->data->sram_2nd_pdn_bit);

		ret = regmap_read_poll_timeout(scpsys->base, pd->data->sram_2nd_ctrl_offs,
					       tmp, (tmp & pdn_2nd_ack) == 0, MTK_POLL_DELAY_US,
					       MTK_POLL_TIMEOUT);
		if (ret)
			return ret;
	}
	if (pd->data->sram_clk_iso_bit) {
		mtk_regmap_clear_bits(scpsys->base, pd->data->sram_ctrl_offs,
				      pd->data->sram_clk_iso_bit);
	}
	if (pd->data->sram_clk_dis_bit) {
		mtk_regmap_clear_bits(scpsys->base, pd->data->sram_ctrl_offs,
				      pd->data->sram_clk_dis_bit);
	}
	if (pd->data->sram_2nd_clk_iso_bit) {
		mtk_regmap_clear_bits(scpsys->base, pd->data->sram_2nd_ctrl_offs,
				      pd->data->sram_2nd_clk_iso_bit);
	}
	if (pd->data->sram_2nd_clk_dis_bit) {
		mtk_regmap_clear_bits(scpsys->base, pd->data->sram_2nd_ctrl_offs,
				      pd->data->sram_2nd_clk_dis_bit);
	}

	return 0;
}

static void scpsys_sram_disable(struct scpsys_domain *pd)
{
	struct scpsys *scpsys = pd->scpsys;

	if (pd->data->sram_2nd_clk_dis_bit) {
		mtk_regmap_set_bits(scpsys->base, pd->data->sram_2nd_ctrl_offs,
				    pd->data->sram_2nd_clk_dis_bit);
	}
	if (pd->data->sram_clk_iso_bit) {
		mtk_regmap_set_bits(scpsys->base, pd->data->sram_ctrl_offs,
				    pd->data->sram_clk_iso_bit);
		udelay(1);
	}
	if (pd->data->sram_pdn_bit) {
		mtk_regmap_set_bits(scpsys->base, pd->data->sram_ctrl_offs,
				    pd->data->sram_pdn_bit);
	}

	if (pd->data->sram_2nd_clk_iso_bit) {
		mtk_regmap_set_bits(scpsys->base, pd->data->sram_2nd_ctrl_offs,
				    pd->data->sram_2nd_clk_iso_bit);
		udelay(1);
	}
	if (pd->data->sram_2nd_pdn_bit) {
		mtk_regmap_set_bits(scpsys->base, pd->data->sram_2nd_ctrl_offs,
				    pd->data->sram_2nd_pdn_bit);
	}
}

static int scpsys_power_on(struct generic_pm_domain *genpd)
{
	struct scpsys_domain *pd = container_of(genpd, struct scpsys_domain, genpd);
	struct scpsys *scpsys = pd->scpsys;
	bool tmp;
	int ret;

	/* subsys power on */
	mtk_regmap_set_bits(scpsys->base, pd->data->pwr_on_offs, pd->data->pwr_on_bit);
	mtk_regmap_set_bits(scpsys->base, pd->data->pwr_on_2nd_offs, pd->data->pwr_on_2nd_bit);

	/* wait until PWR_ACK = 1 */
	ret = readx_poll_timeout(scpsys_domain_is_on, pd, tmp, tmp,
				 MTK_POLL_DELAY_US, MTK_POLL_TIMEOUT);
	if (ret)
		return ret;

	udelay(30);

	if (pd->data->pwr_clamp_bit) {
		mtk_regmap_clear_bits(scpsys->base, pd->data->pwr_on_offs,
				      pd->data->pwr_clamp_bit);
		udelay(30);
	}

	if (pd->data->pwr_rst_bit)
		mtk_regmap_set_bits(scpsys->base, pd->data->pwr_on_offs, pd->data->pwr_rst_bit);

	ret = scpsys_sram_enable(pd);
	if (ret)
		goto err;

	return 0;

err:
	scpsys_sram_disable(pd);

	return ret;
}

static int scpsys_power_off(struct generic_pm_domain *genpd)
{
	struct scpsys_domain *pd = container_of(genpd, struct scpsys_domain, genpd);
	struct scpsys *scpsys = pd->scpsys;

	scpsys_sram_disable(pd);

	if (pd->data->pwr_clamp_bit) {
		mtk_regmap_set_bits(scpsys->base, pd->data->pwr_on_offs, pd->data->pwr_clamp_bit);
		udelay(30);
	}

	if (pd->data->pwr_rst_bit)
		mtk_regmap_clear_bits(scpsys->base, pd->data->pwr_on_offs, pd->data->pwr_rst_bit);

	mtk_regmap_clear_bits(scpsys->base, pd->data->pwr_on_offs, pd->data->pwr_on_bit);
	mtk_regmap_clear_bits(scpsys->base, pd->data->pwr_on_2nd_offs, pd->data->pwr_on_2nd_bit);

	return 0;
}

static int scpsys_domain_init(struct scpsys *scpsys, u32 id)
{
	const struct scpsys_domain_data *domain_data;
	struct scpsys_domain *pd;
	int ret;

	domain_data = &scpsys->soc_data->domains_data[id];
	if (domain_data->sta_mask == 0) {
		dev_err(scpsys->dev, "undefined domain id %d\n", id);
		return -EINVAL;
	}

	pd = devm_kzalloc(scpsys->dev, sizeof(*pd), GFP_KERNEL);
	if (!pd)
		return -ENOMEM;

	pd->data = domain_data;
	pd->scpsys = scpsys;

	/*
	 * Initially turn on all domains to make the domains usable
	 * with !CONFIG_PM and to get the hardware in sync with the
	 * software.  The unused domains will be switched off during
	 * late_init time.
	 */
	if (MTK_SCPD_CAPS(pd, MTK_SCPD_KEEP_DEFAULT_OFF)) {
		if (scpsys_domain_is_on(pd))
			dev_warn(scpsys->dev, "A default off power domain has been ON\n");
	} else {
		ret = scpsys_power_on(&pd->genpd);
		if (ret < 0) {
			dev_err(scpsys->dev, "failed to power on domain: %d\n", ret);
			return ret;
		}
	}

	if (scpsys->domains[id]) {
		dev_err(scpsys->dev, "power domain %d already exists\n", id);
		return -EINVAL;
	}

	pd->genpd.name = domain_data->name;
	pd->genpd.power_off = scpsys_power_off;
	pd->genpd.power_on = scpsys_power_on;

	if (MTK_SCPD_CAPS(pd, MTK_SCPD_ACTIVE_WAKEUP))
		pd->genpd.flags |= GENPD_FLAG_ACTIVE_WAKEUP;

	if (MTK_SCPD_CAPS(pd, MTK_SCPD_KEEP_DEFAULT_OFF))
		pm_genpd_init(&pd->genpd, NULL, true);
	else
		pm_genpd_init(&pd->genpd, NULL, false);

	scpsys->domains[id] = &pd->genpd;

	return 0;
}

static int scpsys_domain_deinit(struct scpsys_domain *pd)
{
	if (scpsys_domain_is_on(pd))
		scpsys_power_off(&pd->genpd);

	return pm_genpd_remove(&pd->genpd);
}

static void scpsys_domains_cleanup(struct scpsys *scpsys)
{
	struct generic_pm_domain *genpd;
	struct scpsys_domain *pd;
	int i;

	for (i = scpsys->soc_data->num_domains - 1; i >= 0; i--) {
		genpd = scpsys->domains[i];
		if (genpd) {
			pd = container_of(genpd, struct scpsys_domain, genpd);
			scpsys_domain_deinit(pd);
		}
	}
}

static const struct of_device_id scpsys_of_match[] = {
	{
		.compatible = "mediatek,mt7988-power-controller",
		.data = &mt7988_scpsys_data,
	},
	{}
};

static int scpsys_probe(struct platform_device *pdev)
{
	const struct scpsys_soc_data *soc_data;
	struct device *dev = &pdev->dev;
	struct scpsys *scpsys;
	int ret;
	int i;

	soc_data = device_get_match_data(dev);
	if (!soc_data)
		return -EFAULT;

	scpsys = devm_kzalloc(dev, struct_size(scpsys, domains, soc_data->num_domains),
					       GFP_KERNEL);
	if (!scpsys)
		return -ENOMEM;

	scpsys->base = syscon_node_to_regmap(dev->of_node);
	if (IS_ERR(scpsys->base))
		return PTR_ERR(scpsys->base);

	scpsys->dev = dev;
	scpsys->soc_data = soc_data;
	for (i = 0; i < soc_data->num_domains; i++) {
		ret = scpsys_domain_init(scpsys, i);
		if (ret)
			goto err;
	}

	scpsys->pd_data.domains = scpsys->domains;
	scpsys->pd_data.num_domains = soc_data->num_domains;
	ret = of_genpd_add_provider_onecell(dev->of_node, &scpsys->pd_data);
	if (ret)
		goto err;

	return 0;
err:
	scpsys_domains_cleanup(scpsys);

	return ret;
}

static struct platform_driver scpsys_pm_domain_driver = {
	.probe = scpsys_probe,
	.driver = {
		.name = "mtk-power-controller-mt7988",
		.suppress_bind_attrs = true,
		.of_match_table = scpsys_of_match,
	},
};
builtin_platform_driver(scpsys_pm_domain_driver);
