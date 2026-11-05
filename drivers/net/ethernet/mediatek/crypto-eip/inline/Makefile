# SPDX-License-Identifier: GPL-2.0-or-later
#
# Copyright (C) 2023 MediaTek Inc.
#
# Author: Chris.Chou <chris.chou@mediatek.com>
#         Ren-Ting Wang <ren-ting.wang@mediatek.com>

obj-$(CONFIG_MTK_CRYPTO_EIP_INLINE) += crypto-eip-inline.o

# the DDK include paths come from ../Makefile (subdir-ccflags-y)
ccflags-y += -I$(src)/inc
ccflags-y += -I$(srctree)/drivers/net/ethernet/mediatek
ccflags-y += -I$(srctree)/drivers/net/ethernet/mediatek/pce/inc

crypto-eip-inline-y += init.o
crypto-eip-inline-y += ddk-wrapper.o
crypto-eip-inline-y += debugfs.o
crypto-eip-inline-y += xfrm-offload.o
