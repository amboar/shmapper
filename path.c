// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2020,2021 IBM Corp.

#include "path.h"

#include <errno.h>
#include <string.h>

struct shmapper_path_map {
	struct shmap_map __as_shared *paths;
};

struct shmapper_path_map __as_shared *
shmapper_path_map_init(struct shmap *shmap)
{
	struct shmapper_path_map __as_shared *map;

	map = shmap_malloc(shmap, sizeof(*map));
	if (!map)
		goto err;

	shmap_private(shmap, map)->paths = shmap_map_init(shmap);
	if (!shmap_private(shmap, map)->paths)
		goto cleanup_map;

	return map;

cleanup_map:
	shmap_free(shmap, map);
err:
	return NULL;
}

static struct shmapper_connection_map __as_shared *
__shmapper_path_map_get(struct shmap *shmap,
			const struct shmapper_path_map __as_shared *map,
			const shmapper_path_t key)
{
	struct shmapper_connection_map __as_shared *conns;

	conns = shmap_map_get(shmap, shmap_private(shmap, map)->paths, key.path,
			      strlen(key.path));

	return conns;
}

static void
shmapper_path_map_clear(struct shmap *shmap,
			struct shmapper_path_map __as_shared *map)
{
	struct shmapper_path_map_iter_entry entry;

	foreach_shmapper_path(shmap, map, entry) {
		struct shmapper_connection_map __as_shared *conns;
		shmapper_path_t path;

		path = shmapper_path_map_iter_entry_key(shmap, &entry);
		conns = shmapper_path_map_remove(shmap, map, path);
		if (conns)
			shmapper_connection_map_destroy(shmap, conns);
	}
}

void shmapper_path_map_destroy(struct shmap *shmap,
			       struct shmapper_path_map __as_shared *map)
{
	shmapper_path_map_clear(shmap, map);
	shmap_map_destroy(shmap, shmap_private(shmap, map)->paths);
	shmap_free(shmap, map);
}

int
shmapper_path_map_add(struct shmap *shmap,
		      struct shmapper_path_map __as_shared *map,
		      const shmapper_path_t path,
		      struct shmapper_connection_map __as_shared *connections)
{
	char __as_shared *shared;

	if (shmapper_path_map_get(shmap, map, path))
		return -EEXIST;

	shared = shmap_strdup(shmap, path.path);
	if (!shared)
		return -ENOMEM;

	return shmap_map_add(shmap, shmap_private(shmap, map)->paths, shared,
			     strlen(path.path), connections);
}

struct shmapper_connection_map __as_shared *
shmapper_path_map_remove(struct shmap *shmap,
			 struct shmapper_path_map __as_shared *map,
			 const shmapper_path_t path)
{
	struct shmap_map_entry e;
	int rc;

	e = shmap_map_entry(shmap, shmap_private(shmap, map)->paths, path.path,
			    strlen(path.path));

	if (!e.key)
		return NULL;

	rc = shmap_map_remove(shmap, shmap_private(shmap, map)->paths,
			      path.path, strlen(path.path));
	if (rc < 0)
		return NULL;

	shmap_free(shmap, e.key);

	return e.value;
}

int
shmapper_path_map_add_interface(struct shmap *shmap,
				struct shmapper_path_map __as_shared *map,
				const shmapper_path_t path,
				const shmapper_connection_t connection,
				const shmapper_interface_t interface)
{
	struct shmapper_connection_map __as_shared *conns;
	int rc;

	conns = __shmapper_path_map_get(shmap, map, path);
	if (!conns) {
		conns = shmapper_connection_map_init(shmap);
		if (!conns)
			return -ENOMEM;
	}

	rc = shmapper_connection_map_add_interface(shmap, conns, connection,
						   interface);
	if (rc < 0)
		goto cleanup_connection_map;

	rc = shmapper_path_map_add(shmap, map, path, conns);
	if (rc < 0 && rc != -EEXIST)
		goto cleanup_add_interface;

	return 0;

cleanup_add_interface:
	shmapper_connection_map_remove_interface(shmap, conns, connection,
						 interface);

cleanup_connection_map:
	if (!__shmapper_path_map_get(shmap, map, path))
		shmapper_connection_map_destroy(shmap, conns);

	return rc;
}

int
shmapper_path_map_remove_interface(struct shmap *shmap,
				   struct shmapper_path_map __as_shared *map,
				   const shmapper_path_t path,
				   const shmapper_connection_t connection,
				   const shmapper_interface_t interface)
{
	struct shmapper_connection_map __as_shared *conns;

	conns = __shmapper_path_map_get(shmap, map, path);
	if (!conns)
		return 0;

	return shmapper_connection_map_remove_interface(shmap, conns,
							connection, interface);
}

struct shmapper_path_map_iter_entry
shmapper_path_map_entry(struct shmap *shmap,
			const struct shmapper_path_map __as_shared *map,
			const shmapper_path_t key)
{
	struct shmapper_path_map_iter_entry pentry;
	struct shmap_map_entry entry;

	entry = shmap_map_entry(shmap, shmap_private(shmap, map)->paths,
				key.path, strlen(key.path));

	pentry.path = entry.key;
	pentry.connections = entry.value;

	return pentry;
}

const struct shmapper_connection_map __as_shared *
shmapper_path_map_get(struct shmap *shmap,
		      const struct shmapper_path_map __as_shared *map,
		      const shmapper_path_t key)
{
	return __shmapper_path_map_get(shmap, map, key);
}

struct shmapper_path_map_iter
shmapper_path_map_iter_init(struct shmap *shmap,
			    const struct shmapper_path_map __as_shared *map)
{
	struct shmapper_path_map_iter iter;

	shmap_map_iter_init(shmap, shmap_private(shmap, map)->paths,
			    &iter.iter);
	iter.shmap = shmap;

	return iter;
}

void shmapper_path_map_iter_destroy(struct shmapper_path_map_iter *iter)
{
	shmap_map_iter_destroy(iter->shmap, &iter->iter);
}

bool shmapper_path_map_iter_has_next(struct shmapper_path_map_iter *iter)
{
	return shmap_map_iter_has_next(iter->shmap, &iter->iter);
}

struct shmapper_path_map_iter_entry
shmapper_path_map_iter_next(struct shmapper_path_map_iter *iter)
{
	struct shmapper_path_map_iter_entry pentry;
	struct shmap_map_iter_entry entry;

	entry = shmap_map_iter_next(iter->shmap, &iter->iter);

	pentry.path = entry.key;
	pentry.connections = entry.value;

	return pentry;
}
