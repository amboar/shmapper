/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2020,2021 IBM Corp. */

#ifndef SHMAP_HASH_H
#define SHMAP_HASH_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

struct shmap_hash {
	uint32_t state;
};

static inline void shmap_hash_init(struct shmap_hash *hash)
{
	memset(hash, 0, sizeof(*hash));
}

static inline uint32_t shmap_hash_value(struct shmap_hash *hash)
{
	return hash->state;
}

void shmap_hash_update(struct shmap_hash *hash, const void *buf, size_t len);

uint32_t shmap_hash_object(const void *buf, size_t len);

#endif
