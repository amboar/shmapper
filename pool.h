/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2020,2021 IBM Corp. */

#ifndef SHMAP_POOL_H
#define SHMAP_POOL_H

#include "address.h"
#include "alloc.h"
#include "shmap.h"

#include <pthread.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

struct shmap;
struct shmap_alloc;

/* Lives in shared region */
struct shmap_pool_data {
	/* Constant */
	uint32_t magic;

	/* Modified under shmap's sem */
	uint64_t refs;

	pthread_rwlock_t lock;
	size_t len;

	char data[] __attribute__((aligned(8)));
};

/* Lives in private region */
struct shmap_pool {
	uint32_t flags;
	const char *path;

	struct shmap_alloc *alloc;

	int shm;
	size_t len;
	struct shmap_pool_data __as_private *base;
};

int shmap_pool_init(struct shmap_pool *pool, const char *name, uint32_t flags);
int shmap_pool_destroy(struct shmap_pool *pool);
int shmap_pool_contains(struct shmap_pool *pool, void *base, size_t len);
ssize_t shmap_pool_grow(struct shmap_pool *pool, intptr_t grow, void **allocated);
int shmap_pool_read_lock(struct shmap_pool *pool);
int shmap_pool_read_unlock(struct shmap_pool *pool);

#endif
