# SPDX-License-Identifier: GPL-2.0+
#
# (C) Copyright 2012
# Texas Instruments Incorporated - http://www.ti.com/
# Aneesh V <aneesh@ti.com>
# Based on common/Makefile.
#

ifdef CONFIG_SPL_BUILD
obj-$(CONFIG_SPL_FRAMEWORK) += spl.o
obj-$(CONFIG_$(SPL_TPL_)BOOTROM_SUPPORT) += spl_bootrom.o
obj-$(CONFIG_$(SPL_TPL_)LOAD_FIT) += spl_fit.o
obj-$(CONFIG_$(SPL_TPL_)NOR_SUPPORT) += spl_nor.o
obj-$(CONFIG_$(SPL_TPL_)XIP_SUPPORT) += spl_xip.o
obj-$(CONFIG_$(SPL_TPL_)YMODEM_SUPPORT) += spl_ymodem.o
ifndef CONFIG_SPL_UBI
obj-$(CONFIG_$(SPL_TPL_)NAND_SUPPORT) += spl_nand.o
obj-$(CONFIG_$(SPL_TPL_)ONENAND_SUPPORT) += spl_onenand.o
endif
obj-$(CONFIG_$(SPL_TPL_)UBI) += spl_ubi.o
obj-$(CONFIG_$(SPL_TPL_)NET_SUPPORT) += spl_net.o
obj-$(CONFIG_$(SPL_TPL_)MMC_SUPPORT) += spl_mmc.o
obj-$(CONFIG_$(SPL_TPL_)ATF) += spl_atf.o
obj-$(CONFIG_$(SPL_TPL_)USB_SUPPORT) += spl_usb.o
obj-$(CONFIG_$(SPL_TPL_)FAT_SUPPORT) += spl_fat.o
obj-$(CONFIG_$(SPL_TPL_)EXT_SUPPORT) += spl_ext.o
obj-$(CONFIG_$(SPL_TPL_)SATA_SUPPORT) += spl_sata.o
obj-$(CONFIG_$(SPL_TPL_)DFU_SUPPORT) += spl_dfu.o
obj-$(CONFIG_$(SPL_TPL_)SPI_LOAD) += spl_spi.o
obj-$(CONFIG_$(SPL_TPL_)RAM_SUPPORT) += spl_ram.o
obj-$(CONFIG_$(SPL_TPL_)USB_SDP_SUPPORT) += spl_sdp.o

obj-$(CONFIG_$(SPL_TPL_)SLI_EXTENSIONS) += sli/sli_io.o
obj-$(CONFIG_$(SPL_TPL_)SLI_EXTENSIONS) += sli/sli_control.o
obj-$(CONFIG_$(SPL_TPL_)SLI_EXTENSIONS) += sli/sli_manifest.o
obj-$(CONFIG_$(SPL_TPL_)SLI_EXTENSIONS) += sli/sli_list.o
obj-$(CONFIG_$(SPL_TPL_)SLI_EXTENSIONS) += sli/sli_params.o
obj-$(CONFIG_$(SPL_TPL_)SLI_EXTENSIONS) += sli/sli_coretee.o
obj-$(CONFIG_$(SPL_TPL_)SLI_EXTENSIONS) += sli/sli_component.o
obj-$(CONFIG_$(SPL_TPL_)SLI_EXTENSIONS) += sli/sli_bootstates.o
obj-$(CONFIG_$(SPL_TPL_)SLI_EXTENSIONS) += sli/sli_update.o
obj-$(CONFIG_$(SPL_TPL_)SLI_EXTENSIONS) += sli/asn1/asn1parse.o
obj-$(CONFIG_$(SPL_TPL_)SLI_EXTENSIONS) += sli/asn1/asn1utils.o
obj-$(CONFIG_$(SPL_TPL_)SLI_EXTENSIONS) += sli/sli_prov.o
endif
