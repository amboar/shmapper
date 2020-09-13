// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2020,2021 IBM Corp.

#include "connection.h"

#include <errno.h>
#include <string.h>

struct shmapper_connection_map {
	struct shmap_map __as_shared *connections;
};

struct shmapper_connection_map __as_shared *
shmapper_connection_map_init(struct shmap *shmap)
{
	struct shmapper_connection_map __as_shared *map;
	struct shmap_map __as_shared *connections;

	/* TODO: Optimise memory use, wrt allocator overhead */

	map = shmap_malloc(shmap, sizeof(*map));
	if (!map)
		goto err;

	connections = shmap_map_init(shmap);
	if (!connections)
		goto cleanup_map;

	shmap_private(shmap, map)->connections = connections;

	return map;

cleanup_map:
	shmap_free(shmap, map);
err:
	return NULL;
}

static struct shmapper_interface_set __as_shared *
__shmapper_connection_map_get(struct shmap *shmap,
			  const struct shmapper_connection_map __as_shared *map,
			  const shmapper_connection_t connection)
{
	struct shmapper_interface_set __as_shared *set;

	set = shmap_map_get(shmap, shmap_private(shmap, map)->connections,
			    connection.connection,
			    strlen(connection.connection) + 1);

	return set;
}

static void
shmapper_connection_map_clear(struct shmap *shmap,
			      struct shmapper_connection_map __as_shared *map)
{
	struct shmapper_connection_map_iter_entry entry;

	foreach_shmapper_connection(shmap, map, entry) {
		struct shmapper_interface_set __as_shared *ifaces;
		shmapper_connection_t conn;

		conn = shmapper_connection_map_iter_entry_key(shmap, &entry);

		ifaces = shmapper_connection_map_remove(shmap, map, conn);
		if (ifaces)
			shmapper_interface_set_destroy(shmap, ifaces);
	}
}

void
shmapper_connection_map_destroy(struct shmap *shmap,
			        struct shmapper_connection_map __as_shared *map)
{
	shmapper_connection_map_clear(shmap, map);
	shmap_map_destroy(shmap, shmap_private(shmap, map)->connections);
	shmap_free(shmap, map);
}

int
shmapper_connection_map_add(struct shmap *shmap,
			    struct shmapper_connection_map __as_shared *map,
			    const shmapper_connection_t connection,
			    struct shmapper_interface_set __as_shared *set)
{
	char __as_shared *key;
	int rc;

	if (shmapper_connection_map_get(shmap, map, connection))
		return -EEXIST;

	key = shmap_strdup(shmap, connection.connection);
	if (!key)
		return -ENOMEM;

	rc = shmap_map_add(shmap, shmap_private(shmap, map)->connections, key,
			   strlen(connection.connection) + 1, set);
	if (rc)
		shmap_free(shmap, key);

	return rc;
}

struct shmapper_interface_set __as_shared *
shmapper_connection_map_remove(struct shmap *shmap,
			       struct shmapper_connection_map __as_shared *map,
			       const shmapper_connection_t connection)
{
	struct shmap_map_entry e;
	int rc;

	e = shmap_map_entry(shmap, shmap_private(shmap, map)->connections,
			    connection.connection,
			    strlen(connection.connection) + 1);

	if (!e.key)
		return NULL;

	rc = shmap_map_remove(shmap, shmap_private(shmap, map)->connections,
			      connection.connection,
			      strlen(connection.connection) + 1);
	if (rc < 0)
		return NULL;

	shmap_free(shmap, e.key);

	return e.value;
}

int shmapper_connection_map_add_interface(struct shmap *shmap,
				struct shmapper_connection_map __as_shared *map,
				const shmapper_connection_t connection,
				const shmapper_interface_t interface)
{
	struct shmapper_interface_set __as_shared *ifaces;
	int rc;

	ifaces = __shmapper_connection_map_get(shmap, map, connection);
	if (!ifaces) {
		ifaces = shmapper_interface_set_init(shmap);
		if (!ifaces)
			return -ENOMEM;
	}

	rc = shmapper_interface_set_add(shmap, ifaces, interface);
	if (rc < 0)
		goto cleanup_interface_set;

	rc = shmapper_connection_map_add(shmap, map, connection, ifaces);
	if (rc < 0 && rc != -EEXIST)
		goto cleanup_add_interface;

	return 0;

cleanup_add_interface:
	shmapper_interface_set_remove(shmap, ifaces, interface);

cleanup_interface_set:
	if (!__shmapper_connection_map_get(shmap, map, connection))
		shmapper_interface_set_destroy(shmap, ifaces);

	return rc;
}

int shmapper_connection_map_remove_interface(struct shmap *shmap,
				struct shmapper_connection_map __as_shared *map,
				const shmapper_connection_t connection,
				const shmapper_interface_t interface)
{
	struct shmapper_interface_set __as_shared *ifaces;

	ifaces = __shmapper_connection_map_get(shmap, map, connection);
	if (!ifaces)
		return 0;

	return shmapper_interface_set_remove(shmap, ifaces, interface);
}

const struct shmapper_interface_set __as_shared *
shmapper_connection_map_get(struct shmap *shmap,
			  const struct shmapper_connection_map __as_shared *map,
			  const shmapper_connection_t connection)
{
	return __shmapper_connection_map_get(shmap, map, connection);
}

struct shmapper_connection_map_iter
shmapper_connection_map_iter_init(struct shmap *shmap,
			  const struct shmapper_connection_map __as_shared *map)
{
	struct shmapper_connection_map_iter iter;

	shmap_map_iter_init(shmap, shmap_private(shmap, map)->connections,
			    &iter.iter);
	iter.shmap = shmap;

	return iter;
}

void
shmapper_connection_map_iter_destroy(struct shmapper_connection_map_iter *iter)
{
	shmap_map_iter_destroy(iter->shmap, &iter->iter);
}

bool
shmapper_connection_map_iter_has_next(struct shmapper_connection_map_iter *iter)
{
	return shmap_map_iter_has_next(iter->shmap, &iter->iter);
}

struct shmapper_connection_map_iter_entry
shmapper_connection_map_iter_next(struct shmapper_connection_map_iter *iter)
{
	struct shmapper_connection_map_iter_entry centry;
	struct shmap_map_iter_entry entry;

	entry = shmap_map_iter_next(iter->shmap, &iter->iter);

	centry.connection = entry.key;
	centry.interfaces = entry.value;

	return centry;
}
