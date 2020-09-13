/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2020,2021 IBM Corp. */

#ifndef SHMAP_MAP_H
#define SHMAP_MAP_H

#include "shmap.h"

#include <stdbool.h>

struct shmap_map_entry {
	void __as_shared *key;
	size_t len;
	void __as_shared *value;
};

struct shmap_map;

struct shmap_map __as_shared *shmap_map_init(struct shmap *shmap);
int shmap_map_destroy(struct shmap *shmap, struct shmap_map __as_shared *map);

size_t shmap_map_size(struct shmap *shmap, struct shmap_map __as_shared *map);

int shmap_map_add(struct shmap *shmap, struct shmap_map __as_shared *map,
		  void __as_shared *key, size_t len, void __as_shared *value);
int shmap_map_remove(struct shmap *shmap, struct shmap_map __as_shared *map,
		     const void __as_private *key, size_t len);
void __as_shared *
shmap_map_get(struct shmap *shmap, struct shmap_map __as_shared *map,
	      const void __as_private *key, size_t len);

struct shmap_map_entry shmap_map_entry(struct shmap *shmap,
				       struct shmap_map __as_shared *map,
				       const void __as_private *key,
				       size_t len);

bool shmap_map_contains(struct shmap *shmap, struct shmap_map __as_shared *map,
		        const void __as_private *key, size_t len);

struct shmap_map_iter {
	const struct shmap_map __as_shared *map;
	size_t curr;
};

void shmap_map_iter_init(struct shmap *shmap,
			 const struct shmap_map __as_shared *map,
			 struct shmap_map_iter *iter);

void shmap_map_iter_destroy(struct shmap *shmap, struct shmap_map_iter *iter);

bool shmap_map_iter_has_next(struct shmap *shmap, struct shmap_map_iter *iter);

struct shmap_map_iter_entry {
	const void __as_shared *key;
	size_t len;
	const void __as_shared *value;
};

struct shmap_map_iter_entry shmap_map_iter_next(struct shmap *shmap,
						struct shmap_map_iter *iter);

#if 0
/* NULL sentinel */
struct shmap_map_entry __as_private *
shmap_map_iter_into_array(struct shmap *shmap, struct shmap_map_iter *iter);

/* NULL sentinel */
struct shmap_map_entry __as_private *
shmap_map_as_array(struct shmap *shmap, struct shmap_map __as_shared *map);
#endif
#endif
