// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2020,2021 IBM Corp.

#include "map.h"
#include "hash.h"
#include "trace.h"

#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

struct shmap_map {
	struct shmap_map_entry __as_shared *vec;
	size_t capacity;
	size_t load;
	/* Percentage of load to capacity */
	size_t threshold;
};

struct shmap_map __as_shared *shmap_map_init(struct shmap *shmap)
{
	struct shmap_map __as_shared *map;
	void __as_shared *vec;
	size_t len;

	map = shmap_malloc(shmap, sizeof(*map));
	if (!map)
		return NULL;

	shmap_private(shmap, map)->load = 0;
	shmap_private(shmap, map)->capacity = 16;
	shmap_private(shmap, map)->threshold = 66;

	len = shmap_private(shmap, map)->capacity * sizeof(*map->vec);
	vec = shmap_malloc(shmap, len);
	if (!vec)
		goto cleanup_map;

	memset(shmap_private(shmap, vec), '\0', len);

	shmap_private(shmap, map)->vec = vec;

	shmap_trace("Have map vector @ %p\n", shmap_private(shmap, vec));

	return map;

cleanup_map:
	shmap_free(shmap, map);

	return NULL;
}

int shmap_map_destroy(struct shmap *shmap, struct shmap_map __as_shared *map)
{
	shmap_free(shmap, shmap_private(shmap, map)->vec);
	shmap_free(shmap, map);

	return 0;
}

size_t shmap_map_size(struct shmap *shmap, struct shmap_map __as_shared *map)
{
	return shmap_private(shmap, map)->load;
}

static int shmap_map_entry_eq(struct shmap *shmap,
			      struct shmap_map_entry __as_shared *entry,
			      const void __as_private *key, size_t len)
{
	assert(shmap_private(shmap, entry));
	assert(key);
	assert(len);

	if (!shmap_private(shmap, entry)->key)
		return 0;

	assert(shmap_private(shmap, entry)->len);

	if (shmap_private(shmap, entry)->len != len)
		return 0;

	return !memcmp(shmap_private(shmap, shmap_private(shmap, entry)->key),
		       key, len);
}

static struct shmap_map_entry __as_shared *
__shmap_map_get(struct shmap *shmap, struct shmap_map __as_shared *map,
		const void __as_private *key, size_t len)
{
	struct shmap_map_entry __as_private *base;
	struct shmap_map_entry __as_private *curr;
	size_t capacity;
	uint32_t val;
	uint32_t idx;

	if (!(key && len))
		return NULL;

	if (!shmap_private(shmap, map)->load)
		return NULL;

	capacity = shmap_private(shmap, map)->capacity;

	shmap_trace("load: %zu, capacity: %zu\n",
		    shmap_private(shmap, map)->load, capacity);
	assert(shmap_private(shmap, map)->load < capacity);

	val = shmap_hash_object(key, len);
	base = shmap_private(shmap, shmap_private(shmap, map)->vec);
	idx = val % capacity;
	do {
		curr = &base[idx];

		if (shmap_map_entry_eq(shmap, shmap_shared(shmap, curr), key,
				       len))
			return shmap_shared(shmap, curr);

		idx = (idx + 1) % capacity;
	} while ((curr->key || curr->len == SIZE_MAX));

	return NULL;
}

void __as_shared *
shmap_map_get(struct shmap *shmap, struct shmap_map __as_shared *map,
	      const void __as_private *key, size_t len)
{
	struct shmap_map_entry __as_shared *entry;

	entry = __shmap_map_get(shmap, map, key, len);

	return entry ? shmap_private(shmap, entry)->value : NULL;
}

struct shmap_map_entry
shmap_map_entry(struct shmap *shmap, struct shmap_map __as_shared *map,
		const void __as_private *key, size_t len)
{
	struct shmap_map_entry __as_shared *e;

	e = __shmap_map_get(shmap, map, key, len);
	if (!e) {
		struct shmap_map_entry ret = {0};
		return ret;
	}

	return *shmap_private(shmap, e);
}

bool shmap_map_contains(struct shmap *shmap, struct shmap_map __as_shared *map,
		        const void __as_private *key, size_t len)
{
	return __shmap_map_get(shmap, map, key, len) != NULL;
}

static int shmap_map_ensure_capacity(struct shmap *shmap,
				     struct shmap_map __as_shared *map)
{
	struct shmap_map_entry __as_shared *resized;
	struct shmap_map_entry __as_private *old;
	size_t watermark;
	size_t capacity;
	size_t iter;
	size_t len;

	assert(shmap_private(shmap, map)->load <
			shmap_private(shmap, map)->capacity);
	assert(shmap_private(shmap, map)->capacity < (SIZE_MAX / 100));

	watermark = ((shmap_private(shmap, map)->load + 1) * 100) /
			shmap_private(shmap, map)->capacity;

	shmap_trace("watermark: %zu, threshold: %zu\n", watermark,
			shmap_private(shmap, map)->threshold);

	if (shmap_private(shmap, map)->threshold >= watermark)
		return 0;

	capacity = 2 * shmap_private(shmap, map)->capacity;
	len = capacity * sizeof(*map->vec);
	resized = shmap_malloc(shmap, len);
	if (!resized)
		return -ENOMEM;

	memset(shmap_private(shmap, resized), '\0', len);

	old = shmap_private(shmap, shmap_private(shmap, map)->vec);
	for (iter = 0; iter < shmap_private(shmap, map)->capacity; old++, iter++) {
		struct shmap_map_entry __as_private *curr;
		uint32_t val;
		uint32_t idx;

		shmap_trace("Using old: %p at iter %zu with key %p\n",
			    old, iter, old->key);

		if (!old->key)
			continue;

		val = shmap_hash_object(shmap_private(shmap, old->key),
					old->len);
		idx = val % capacity;
		do {
			curr = &(shmap_private(shmap, resized)[idx]);

			idx = (idx + 1) % capacity;
		} while (curr->key); /* New allocation, no tombstones */

		assert(idx != (val % capacity));

		assert(old->key);
		curr->key = old->key;

		assert(old->len);
		curr->len = old->len;

		/* Caller can set the value as NULL if they like */
		curr->value = old->value;
	}

	old = shmap_private(shmap, shmap_private(shmap, map)->vec);
	shmap_private(shmap, map)->vec = resized;
	shmap_free(shmap, shmap_shared(shmap, old));

	shmap_private(shmap, map)->capacity = capacity;

	return 0;
}

/*
 * Pre-condition: key may exist in the map
 * Post-condition: key exists in the map
 */
int shmap_map_add(struct shmap *shmap, struct shmap_map __as_shared *map,
		  void __as_shared *key, size_t len, void __as_shared *value)
{
	struct shmap_map_entry __as_private *base;
	struct shmap_map_entry __as_private *curr;
	size_t capacity;
	uint32_t val;
	uint32_t idx;
	int rc;

	if (!(key && len))
		return -EINVAL;

	if (shmap_map_contains(shmap, map, shmap_private(shmap, key), len))
		return 0;

	if ((rc = shmap_map_ensure_capacity(shmap, map)))
		return rc;

	capacity = shmap_private(shmap, map)->capacity;

	/* Only store private pointer after shmap_map_ensure_capacity */
	base = shmap_private(shmap, shmap_private(shmap, map)->vec);
	val = shmap_hash_object(shmap_private(shmap, key), len);
	idx = val % capacity;

	do {
		curr = &base[idx];

		idx = (idx + 1) % capacity;
	} while (curr->key && idx != (val % capacity));

	assert(idx != (val % capacity));
	assert(!curr->key);
	assert(!curr->len || curr->len == SIZE_MAX); /* Tombstone */

	curr->key = key;
	curr->len = len;
	curr->value = value;

	shmap_private(shmap, map)->load++;

	return 0;
}

/*
 * Pre-condition: key may exist in the map
 * Post-condition: key does not exist in the map
 */ 
int shmap_map_remove(struct shmap *shmap, struct shmap_map __as_shared *map,
		     const void __as_private *key, size_t len)
{
	struct shmap_map_entry __as_private *base;
	struct shmap_map_entry __as_private *curr;
	size_t capacity;
	uint32_t val;
	uint32_t idx;

	if (!(key && len))
		return -EINVAL;

	if (!shmap_private(shmap, map)->load)
		return 0;

	capacity = shmap_private(shmap, map)->capacity;

	base = shmap_private(shmap, shmap_private(shmap, map)->vec);
	val = shmap_hash_object(key, len);
	idx = val % capacity;

	do {
		curr = &base[idx];
		idx = (idx + 1) % capacity;
	} while ((curr->key || curr->len == SIZE_MAX) &&
			!shmap_map_entry_eq(shmap, shmap_shared(shmap, curr),
					    key, len));

	if (idx == (val % capacity))
		return 0;

	assert(curr >= base && curr < (base + capacity));

	curr->key = NULL;
	curr->len = SIZE_MAX; /* Tombstone */
	curr->value = NULL;

	shmap_private(shmap, map)->load--;

	return 0;
}

void shmap_map_iter_init(struct shmap *shmap __attribute__((unused)),
			 const struct shmap_map __as_shared *map,
			 struct shmap_map_iter *iter)
{
	iter->map = map;
	iter->curr = 0;
}

void shmap_map_iter_destroy(struct shmap *shmap __attribute__((unused)),
			    struct shmap_map_iter *iter)
{
	iter->map = NULL;
	iter->curr = 0;
}

bool shmap_map_iter_has_next(struct shmap *shmap, struct shmap_map_iter *iter)
{
	const struct shmap_map __as_private *map;
	struct shmap_map_entry __as_private *vec;

	if (!iter->map)
		return false;

	map = shmap_private(shmap, iter->map);
	vec = shmap_private(shmap, map->vec);

	while (iter->curr < map->capacity && !vec[iter->curr].key)
		iter->curr++;

	return iter->curr < map->capacity;
}

struct shmap_map_iter_entry shmap_map_iter_next(struct shmap *shmap,
				       	   struct shmap_map_iter *iter)
{
	const struct shmap_map_entry __as_private *entry;
	const struct shmap_map __as_private *map;
	struct shmap_map_iter_entry ientry;

	if (!shmap_map_iter_has_next(shmap, iter)) {
		memset(&ientry, '\0', sizeof(entry));
		return ientry;
	}

	map = shmap_private(shmap, iter->map);
	entry = &shmap_private(shmap, map->vec)[iter->curr];

	iter->curr++;

	ientry.key = entry->key;
	ientry.len = entry->len;
	ientry.value = entry->value;

	return ientry;
}
