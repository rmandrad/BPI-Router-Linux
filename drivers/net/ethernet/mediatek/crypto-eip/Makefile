# SPDX-License-Identifier: GPL-2.0-or-later
#
# Copyright (C) 2023 MediaTek Inc.
#
# Author: Chris.Chou <chris.chou@mediatek.com>
#         Ren-Ting Wang <ren-ting.wang@mediatek.com>

obj-$(CONFIG_MTK_CRYPTO_EIP_DDK) += ddk/
obj-$(CONFIG_MTK_CRYPTO_EIP_INLINE) += inline/

# The DDK is configured through these paths and defines; they apply to every
# DDK subdirectory. Must be subdir-ccflags-y: kbuild ignores subdir-ccflags-m,
# which is what $(CONFIG_...) expands to for a module-only symbol. Nothing else
# is built below this directory, so the flags do not leak anywhere.
ddk_inc := $(src)/ddk/inc/crypto-eip/ddk

subdir-ccflags-y += \
	-I$(src)/ddk/inc \
	-I$(ddk_inc) \
	-I$(ddk_inc)/configs \
	-I$(ddk_inc)/shdevxs \
	-I$(ddk_inc)/umdevxs \
	-I$(ddk_inc)/device \
	-I$(ddk_inc)/device/lkm \
	-I$(ddk_inc)/device/lkm/of \
	-I$(ddk_inc)/dmares \
	-I$(ddk_inc)/firmware_api \
	-I$(ddk_inc)/kit/builder/sa \
	-I$(ddk_inc)/kit/builder/token \
	-I$(ddk_inc)/kit/eip197 \
	-I$(ddk_inc)/kit/iotoken \
	-I$(ddk_inc)/kit/list \
	-I$(ddk_inc)/kit/ring \
	-I$(ddk_inc)/libc \
	-I$(ddk_inc)/log \
	-I$(ddk_inc)/slad \
	-I$(ddk_inc)/slad/lkm \
	-DEIP197_BUS_VERSION_AXI3 \
	-DDRIVER_64BIT_HOST \
	-DDRIVER_64BIT_DEVICE \
	-DADAPTER_AUTO_TOKENBUILDER
