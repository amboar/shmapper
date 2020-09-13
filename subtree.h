/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2020,2021 IBM Corp. */

#ifndef SHMAPPER_SUBTREE_H
#define SHMAPPER_SUBTREE_H

#include "path.h"
#include "shmap.h"

struct shmapper_subtree_iter {
	struct shmap *shmap;
	struct shmapper_path_map_iter iter;
	shmapper_path_t root;
	struct shmapper_path_map_iter_entry entry;
};

struct shmapper_subtree_iter
shmapper_subtree_iter_init(struct shmap *shmap,
			   const struct shmapper_path_map __as_shared *paths,
			   shmapper_path_t root);

void shmapper_subtree_iter_destroy(struct shmapper_subtree_iter *iter);

bool shmapper_subtree_iter_has_next(struct shmapper_subtree_iter *iter);

struct shmapper_path_map_iter_entry
shmapper_subtree_iter_next(struct shmapper_subtree_iter *iter);

#define foreach_shmapper_subtree(shmap, iter, entry) \
	for (; shmapper_subtree_iter_has_next(&iter) && (entry = shmapper_subtree_iter_next(&iter)).connections;)
#endif
