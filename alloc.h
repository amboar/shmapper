/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2020,2021 IBM Corp. */

#ifndef SHMAP_ALLOC_H
#define SHMAP_ALLOC_H

#include "address.h"

#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

struct shmap_alloc_pool_ops {
	/* Switch the naming around to refer to the provided pointer */
	void __as_shared *(*xlate_private)(void *ctx, void __as_private *ptr);
	void __as_private *(*xlate_shared)(void *ctx, void __as_shared *ptr);
	int (*contains)(void *ctx, void __as_private *base, size_t len);
	ssize_t (*grow)(void *ctx, intptr_t grow, void **allocated);
};

struct shmap_alloc_pool;

/* Lives in process-private memory */
struct shmap_alloc {
	struct shmap_alloc_pool __as_private *pool;
	struct shmap_alloc_pool_ops ops;
	void *ctx;
};

struct shmap_alloc *
shmap_alloc_init_ops(const struct shmap_alloc_pool_ops *ops, void *ctx,
		     void __as_private *base, size_t len, uint32_t flags);
void shmap_alloc_destroy(struct shmap_alloc *alloc);
void shmap_alloc_set_user(struct shmap_alloc *alloc, void __as_shared *user);
void __as_shared *shmap_alloc_get_user(struct shmap_alloc *alloc);
void shmap_alloc_remap(struct shmap_alloc *alloc, void *base);

void __as_shared *shmap_alloc_malloc(struct shmap_alloc *alloc, size_t size);
void shmap_alloc_free(struct shmap_alloc *alloc, void __as_shared *ptr);
void __as_shared *shmap_alloc_realloc(struct shmap_alloc *alloc,
				      void __as_shared *ptr, size_t sz);

static inline const void __as_private *
__shmap_alloc_to_private(struct shmap_alloc *alloc,
			 const void __as_shared *pointer)
{
	if (!pointer)
		return NULL;

	return shmap_p_private(alloc->pool, pointer);
}
#define shmap_alloc_to_private(alloc, pointer) \
	((typeof(*pointer) __as_private *) \
		__shmap_alloc_to_private(alloc, pointer))

static inline const void __as_shared *
__shmap_alloc_to_shared(struct shmap_alloc *alloc,
			const void __as_private *pointer)
{
	if (!pointer)
		return NULL;

	assert(shmap_u_private(pointer) > shmap_u_private(alloc->pool));

	return shmap_p_shared(alloc->pool, pointer);
}
#define shmap_alloc_to_shared(alloc, pointer) \
	((typeof(*pointer) __as_shared *) \
		__shmap_alloc_to_shared(alloc, pointer))

#endif
