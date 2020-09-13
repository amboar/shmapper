/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2020,2021 IBM Corp. */

#ifndef SHMAP_ALIGN_H
#define SHMAP_ALIGN_H

#include <assert.h>
#include <stdint.h>

static inline uintptr_t align_up(uintptr_t ptr, uintptr_t align)
{
	assert(ptr + align > ptr);
	return (ptr + align - 1) & ~(align - 1);
}

#endif
