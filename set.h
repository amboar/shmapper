/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2020,2021 IBM Corp. */

#ifndef SHMAP_SET_H
#define SHMAP_SET_H

#include "shmap.h"

#include <stdbool.h>
#include <stdint.h>

struct shmap_set;

struct shmap_set __as_shared *shmap_set_init(struct shmap *shmap);
int shmap_set_destroy(struct shmap *shmap, struct shmap_set __as_shared *set);

size_t shmap_set_size(struct shmap *shmap, struct shmap_set __as_shared *set);

int shmap_set_add(struct shmap *shmap, struct shmap_set __as_shared *set,
		  void __as_shared *obj, size_t len);
void __as_shared *shmap_set_get(struct shmap *shmap,
				struct shmap_set __as_shared *set,
				const void __as_private *obj, size_t len);
int shmap_set_remove(struct shmap *shmap, struct shmap_set __as_shared *set,
		     const void __as_private *obj, size_t len);
bool shmap_set_contains(struct shmap *shmap, struct shmap_set __as_shared *set,
		        const void __as_private *obj, size_t len);

struct shmap_set_iter {
	const struct shmap_set __as_shared *set;
	uintptr_t cursor;
};

struct shmap_set_iter_entry {
	const void __as_shared *key;
	size_t len;
};

int shmap_set_iter_init(struct shmap *shmap,
			const struct shmap_set __as_shared *set,
			struct shmap_set_iter *iter);
void shmap_set_iter_destroy(struct shmap *shmap, struct shmap_set_iter *iter);

bool shmap_set_iter_has_next(struct shmap *shmap, struct shmap_set_iter *iter);
struct shmap_set_iter_entry shmap_set_iter_next(struct shmap *shmap,
						struct shmap_set_iter *iter);

#if 0
/* NULL sentinel */
struct shmap_set_entry __as_private *
shmap_set_iter_into_array(struct shmap *shmap, struct shmap_set_iter *iter);

/* NULL sentinel */
struct shmap_set_entry __as_private *
shmap_set_as_array(struct shmap *shmap, struct shmap_set __as_shared *map);
#endif
#endif
