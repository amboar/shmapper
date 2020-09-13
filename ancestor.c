// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2020,2021 IBM Corp.

#include "ancestor.h"

#include <errno.h>
#include <libgen.h>
#include <stdlib.h>
#include <string.h>

int
shmapper_ancestor_iter_init(struct shmap *shmap __attribute__((unused)),
			    const struct shmapper_path_map __as_shared *paths,
			    shmapper_path_t target,
			    struct shmapper_ancestor_iter *iter)
{
	iter->path = strdup(target.path);
	if (!iter->path)
		return -errno;

	iter->paths = paths;

	return 0;
}

void shmapper_ancestor_iter_destroy(struct shmap *shmap __attribute__((unused)),
				    struct shmapper_ancestor_iter *iter)
{
	free(iter->path);
}

bool shmapper_ancestor_iter_has_next(struct shmap *shmap,
				     struct shmapper_ancestor_iter *iter)
{
	if (iter->entry.path)
		return true;

	while (strcmp("/", (iter->path = dirname(iter->path))) &&
			!iter->entry.path) {
		iter->entry = shmapper_path_map_entry(shmap, iter->paths,
						     shmapper_path(iter->path));
	}	

	return iter->entry.path;
}

struct shmapper_path_map_iter_entry
shmapper_ancestor_iter_next(struct shmap *shmap,
			    struct shmapper_ancestor_iter *iter)
{
	struct shmapper_path_map_iter_entry pentry;

	if (shmapper_ancestor_iter_has_next(shmap, iter)) {
		pentry = iter->entry;
		iter->entry.path = NULL;
	} else {
		memset(&pentry, '\0', sizeof(pentry));
	}

	return pentry;
}
