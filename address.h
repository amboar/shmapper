/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2020,2021 IBM Corp. */

#ifndef SHMAP_ADDRESS_H
#define SHMAP_ADDRESS_H

#include <assert.h>
#include <stdint.h>

/* sparse annotations */
#if __CHECKER__
#define __as_private	__attribute__((address_space(0)))
#define __as_shared	__attribute__((noderef,address_space(1)))
#define __force		__attribute__((force))
#else
/*
 * Disable the attributes, gcc doesn't understand them and clang is too strict
 * about address spaces: no __attribute__((force)) escape hatch and we need
 * typeof() to work across address spaces
 */
#define __as_private
#define __as_shared
#define __force
#endif

static inline uintptr_t shmap_u_private(const void __as_private *p)
{
	return (uintptr_t __force)p;
}

static inline uintptr_t shmap_u_shared(const void __as_shared *p)
{
	return (uintptr_t __force)p;
}

#define shmap_p_private(_private, _pointer) \
({ \
	(typeof(*_pointer) __as_private __force *)(shmap_u_shared(_pointer) + \
						   shmap_u_private(_private)); \
})

#define shmap_p_shared(_private, _pointer) \
({ \
	(typeof(*_pointer) __as_shared __force *)(shmap_u_private(_pointer) - \
						  shmap_u_private(_private)); \
})

#endif
