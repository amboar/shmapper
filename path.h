/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2020,2021 IBM Corp. */

#ifndef SHMAPPER_PATH_H
#define SHMAPPER_PATH_H

#include "connection.h"
#include "map.h"
#include "shmap.h"

typedef struct {
	const char *path;
} shmapper_path_t;
#define shmapper_path(x)	((shmapper_path_t){x})

struct shmapper_path_map;

struct shmapper_path_map __as_shared *
shmapper_path_map_init(struct shmap *shmap);

void shmapper_path_map_destroy(struct shmap *shmap,
			       struct shmapper_path_map __as_shared *map);

int
shmapper_path_map_add(struct shmap *shmap,
		      struct shmapper_path_map __as_shared *map,
		      const shmapper_path_t path,
		      struct shmapper_connection_map __as_shared *connections);

struct shmapper_connection_map __as_shared *
shmapper_path_map_remove(struct shmap *shmap,
			 struct shmapper_path_map __as_shared *map,
			 const shmapper_path_t path);

int shmapper_path_map_add_interface(struct shmap *shmap,
				    struct shmapper_path_map __as_shared *map,
				    const shmapper_path_t path,
				    const shmapper_connection_t connection,
				    const shmapper_interface_t interface);

int
shmapper_path_map_remove_interface(struct shmap *shmap,
				   struct shmapper_path_map __as_shared *map,
				   const shmapper_path_t path,
				   const shmapper_connection_t connection,
				   const shmapper_interface_t interface);

struct shmapper_path_map_iter_entry
shmapper_path_map_entry(struct shmap *shmap,
			const struct shmapper_path_map __as_shared *map,
			const shmapper_path_t key);

const struct shmapper_connection_map __as_shared *
shmapper_path_map_get(struct shmap *shmap,
		      const struct shmapper_path_map __as_shared *map,
		      const shmapper_path_t key);

struct shmapper_path_map_iter {
	struct shmap *shmap;
	struct shmap_map_iter iter;
};

struct shmapper_path_map_iter_entry {
	const char __as_shared *path;
	const struct shmapper_connection_map __as_shared *connections;
};

static inline shmapper_path_t
shmapper_path_map_iter_entry_key(struct shmap *shmap,
				 struct shmapper_path_map_iter_entry *entry)
{
	return shmapper_path(shmap_private(shmap, entry->path));
}

struct shmapper_path_map_iter
shmapper_path_map_iter_init(struct shmap *shmap,
			    const struct shmapper_path_map __as_shared *map);

void shmapper_path_map_iter_destroy(struct shmapper_path_map_iter *iter);

bool shmapper_path_map_iter_has_next(struct shmapper_path_map_iter *iter);

struct shmapper_path_map_iter_entry
shmapper_path_map_iter_next(struct shmapper_path_map_iter *iter);

#define foreach_shmapper_path(shmap, paths, entry) \
	for (struct shmapper_path_map_iter iter __attribute__((cleanup(shmapper_path_map_iter_destroy))) = shmapper_path_map_iter_init(shmap, paths); \
	       shmapper_path_map_iter_has_next(&iter) && (entry = shmapper_path_map_iter_next(&iter)).connections;)
#endif
