// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2020,2021 IBM Corp.

#include "set.h"
#include "map.h"

#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

struct shmap_set {
	struct shmap_map __as_shared *map;
};

struct shmap_set __as_shared *shmap_set_init(struct shmap *shmap)
{
	struct shmap_set __as_shared *set;
	struct shmap_map __as_shared *map;

	set = shmap_malloc(shmap, sizeof(*set));
	if (!set)
		return NULL;

	map = shmap_map_init(shmap);
	if (!map) {
		shmap_free(shmap, set);
		return NULL;
	}

	shmap_private(shmap, set)->map = map;

	return set;
}

int shmap_set_destroy(struct shmap *shmap, struct shmap_set __as_shared *set)
{
	shmap_map_destroy(shmap, shmap_private(shmap, set)->map);
	shmap_free(shmap, set);

	return 0;
}

size_t shmap_set_size(struct shmap *shmap, struct shmap_set __as_shared *set)
{
	return shmap_map_size(shmap, shmap_private(shmap, set)->map);
}

bool shmap_set_contains(struct shmap *shmap, struct shmap_set __as_shared *set,
		        const void __as_private *obj, size_t len)
{
	return shmap_map_contains(shmap, shmap_private(shmap, set)->map,
				  obj, len);
}

int shmap_set_add(struct shmap *shmap, struct shmap_set __as_shared *set,
		  void __as_shared *obj, size_t len)
{
	return shmap_map_add(shmap, shmap_private(shmap, set)->map, obj, len,
			     NULL);
}

void __as_shared *shmap_set_get(struct shmap *shmap,
				struct shmap_set __as_shared *set,
				const void __as_private *obj, size_t len)
{
	struct shmap_map_entry e;

	e = shmap_map_entry(shmap, shmap_private(shmap, set)->map, obj, len);

	return e.key;
}

int shmap_set_remove(struct shmap *shmap, struct shmap_set __as_shared *set,
		     const void __as_private *obj, size_t len)
{
	return shmap_map_remove(shmap, shmap_private(shmap, set)->map, obj,
				len);
}

int shmap_set_iter_init(struct shmap *shmap,
			const struct shmap_set __as_shared *set,
			struct shmap_set_iter *iter)
{
	struct shmap_map_iter *map_iter;

	map_iter = malloc(sizeof(*iter));
	if (!map_iter)
		return -ENOMEM;

	shmap_map_iter_init(shmap, shmap_private(shmap, set)->map, map_iter);

	iter->set = set;
	iter->cursor = (uintptr_t)map_iter;

	return 0;
}

void shmap_set_iter_destroy(struct shmap *shmap __attribute__((unused)),
			    struct shmap_set_iter *iter)
{
	free((void *)iter->cursor);
	iter->cursor = (uintptr_t)NULL;
	iter->set = NULL;
}


bool shmap_set_iter_has_next(struct shmap *shmap, struct shmap_set_iter *iter)
{
	return shmap_map_iter_has_next(shmap,
				       (struct shmap_map_iter *)iter->cursor);
}

struct shmap_set_iter_entry shmap_set_iter_next(struct shmap *shmap,
						struct shmap_set_iter *iter)
{
	struct shmap_map_iter_entry me;
	struct shmap_set_iter_entry se;

	me = shmap_map_iter_next(shmap, (struct shmap_map_iter *)iter->cursor);

	se.key = me.key;
	se.len = me.len;

	return se;
}
