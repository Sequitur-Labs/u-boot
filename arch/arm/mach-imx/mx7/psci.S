/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright (C) 2015-2016 Freescale Semiconductor, Inc.
 * Copyright 2017 NXP
 */

#include <config.h>
#include <linux/linkage.h>

#include <asm/armv7.h>
#include <asm/arch-armv7/generictimer.h>
#include <asm/psci.h>

	.pushsection ._secure.text, "ax"

	.arch_extension sec

.globl psci_cpu_on
psci_cpu_on:
	push	{r4, r5, lr}

	mov	r4, r0
	mov	r5, r1
	mov	r0, r1
	mov	r1, r2
	mov	r2, r3
	bl	psci_save

	mov	r0, r4
	mov	r1, r5
	ldr	r2, =psci_cpu_entry
	bl	imx_cpu_on

	pop	{r4, r5, pc}

.globl psci_cpu_off
psci_cpu_off:

	bl	psci_cpu_off_common
	bl	psci_get_cpu_id
	bl	imx_cpu_off

1: 	wfi
	b 1b

.globl psci_system_reset
psci_system_reset:
	bl	imx_system_reset

2: 	wfi
	b 2b

.globl psci_system_off
psci_system_off:
	bl	imx_system_off

3: 	wfi
	b 3b

	.popsection
