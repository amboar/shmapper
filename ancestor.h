/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2020,2021 IBM Corp. */

#ifndef SHMAPPER_ANCESTOR_H
#define SHMAPPER_ANCESTOR_H

#include "path.h"
#include "shmap.h"

struct shmapper_ancestor_iter {
	char *path;
	const struct shmapper_path_map __as_shared *paths;
	struct shmapper_path_map_iter_entry entry;
};

int
shmapper_ancestor_iter_init(struct shmap *shmap,
			    const struct shmapper_path_map __as_shared *paths,
			    shmapper_path_t target,
			    struct shmapper_ancestor_iter *iter);

void shmapper_ancestor_iter_destroy(struct shmap *shmap,
				   struct shmapper_ancestor_iter *iter);

bool shmapper_ancestor_iter_has_next(struct shmap *shmap,
				    struct shmapper_ancestor_iter *iter);

struct shmapper_path_map_iter_entry
shmapper_ancestor_iter_next(struct shmap *shmap,
			   struct shmapper_ancestor_iter *iter);

#endif
