// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2020,2021 IBM Corp.

#include "subtree.h"

#include <string.h>

static bool
shmapper_subtree_filter_accept(shmapper_path_t root, shmapper_path_t path)
{
	return !strncmp(root.path, path.path, strlen(root.path));
}

struct shmapper_subtree_iter
shmapper_subtree_iter_init(struct shmap *shmap,
			   const struct shmapper_path_map __as_shared *paths,
			   shmapper_path_t root)
{
	struct shmapper_subtree_iter iter;

	iter.shmap = shmap;
	iter.iter = shmapper_path_map_iter_init(shmap, paths);
	iter.root = root;
	iter.entry.path = NULL;

	return iter;
}

void shmapper_subtree_iter_destroy(struct shmapper_subtree_iter *iter)
{
	shmapper_path_map_iter_destroy(&iter->iter);
}

bool shmapper_subtree_iter_has_next(struct shmapper_subtree_iter *iter)
{
	if (iter->entry.path)
		return true;

	while (shmapper_path_map_iter_has_next(&iter->iter)) {
		shmapper_path_t path;

		iter->entry = shmapper_path_map_iter_next(&iter->iter);
		path = shmapper_path_map_iter_entry_key(iter->shmap,
							&iter->entry);

		if (shmapper_subtree_filter_accept(iter->root, path))
			return true;
	}

	iter->entry.path = NULL;

	return false;
}

struct shmapper_path_map_iter_entry
shmapper_subtree_iter_next(struct shmapper_subtree_iter *iter)
{
	struct shmapper_path_map_iter_entry entry;

	if (shmapper_subtree_iter_has_next(iter)) {
		entry = iter->entry;
		iter->entry.path = NULL;
	} else {
		memset(&entry, '\0', sizeof(entry));
	}

	return entry;
}
