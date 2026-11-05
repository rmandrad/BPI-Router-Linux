# SPDX-License-Identifier: GPL-2.0-or-later
#
# Copyright (c) 2026 MediaTek Inc. All Rights Reserved.
#
# Author: Chris Chou <chris.chou@mediatek.com>

obj-$(CONFIG_MTK_NPU_FLOW) += npu-flow.o

ccflags-y += -I$(src)/../inc
ccflags-y += -I$(src)/../protocol/inc
ccflags-y += -I$(src)/inc
ccflags-y += -I$(srctree)/drivers/net/ethernet/mediatek
ccflags-y += -I$(srctree)/drivers/net/ethernet/mediatek/pce/inc

npu-flow-y += init.o
npu-flow-y += net-event.o
npu-flow-y += tnl-offload.o
