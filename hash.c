// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2020,2021 IBM Corp.

#if 1
#ifndef NTRACE
#define NTRACE
#endif
#endif

#include "hash.h"
#include "trace.h"

#include <inttypes.h>
#include <stdint.h>

static inline uint8_t rot8(uint8_t val, uint8_t n)
{
	uint8_t res;

	n %= 8;

	res = ((uint16_t)val << n) | (val >> (8U - n));

	shmap_trace("val: 0x%02" PRIx8 ", n: %" PRIu8 ", res: 0x%02" PRIx8 "\n",
		    val, n, res);

	return res;
}

/* Dodgy hash function */
static void shmap_hash_update_1(struct shmap_hash *hash, uint8_t curr)
{
	uint32_t curr4;

	/* Rotate */
	hash->state = (hash->state << 1) | (!!(hash->state & 0x80000000ULL));

	/* Splat */
	curr4 = ((uint32_t)rot8(curr, 6) << 24U) |
		((uint32_t)rot8(curr, 4) << 16U) |
		((uint32_t)rot8(curr, 2) <<  8U) |
		((uint32_t)curr);

	shmap_trace("curr: 0x%02" PRIx8 ", curr4: 0x%08" PRIx32 "\n",
		    curr, curr4);

	/* Mix */
	hash->state ^= curr4;

	shmap_trace("State after update: 0x%08" PRIx32 "\n", hash->state);
}

void shmap_hash_update(struct shmap_hash *hash, const void *buf, size_t len)
{
	shmap_trace("Updating 0x%08" PRIx32 " with %p for %zu\n",
		    hash->state, buf, len);

	for (; len > 0; len--)
		shmap_hash_update_1(hash, *(uint8_t *)buf++);

	shmap_trace("Update complete, current state: 0x%08" PRIx32 "\n",
		    hash->state);
}

uint32_t shmap_hash_object(const void *obj, size_t len)
{
	struct shmap_hash _hash, *hash = &_hash;

	shmap_hash_init(hash);
	shmap_hash_update(hash, obj, len);

	return shmap_hash_value(hash);
}
