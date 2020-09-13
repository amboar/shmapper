/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2020,2021 IBM Corp. */

#ifndef SHMAPPER_CONNECTION_H
#define SHMAPPER_CONNECTION_H

#include "interface.h"
#include "map.h"
#include "shmap.h"

typedef struct {
	const char *connection;
} shmapper_connection_t;
#define shmapper_connection(x)	((shmapper_connection_t){x})

struct shmapper_connection_map;

struct shmapper_connection_map __as_shared *
shmapper_connection_map_init(struct shmap *shmap);

void
shmapper_connection_map_destroy(struct shmap *shmap,
			       struct shmapper_connection_map __as_shared *map);

int shmapper_connection_map_add(struct shmap *shmap,
				struct shmapper_connection_map __as_shared *map,
				const shmapper_connection_t connection,
				struct shmapper_interface_set __as_shared *set);

struct shmapper_interface_set __as_shared *
shmapper_connection_map_remove(struct shmap *shmap,
			       struct shmapper_connection_map __as_shared *map,
			       const shmapper_connection_t connection);

int shmapper_connection_map_add_interface(struct shmap *shmap,
				struct shmapper_connection_map __as_shared *map,
				const shmapper_connection_t connection,
				const shmapper_interface_t interface);

int shmapper_connection_map_remove_interface(struct shmap *shmap,
				struct shmapper_connection_map __as_shared *map,
				const shmapper_connection_t connection,
				const shmapper_interface_t interface);

const struct shmapper_interface_set __as_shared *
shmapper_connection_map_get(struct shmap *shmap,
			  const struct shmapper_connection_map __as_shared *map,
			  const shmapper_connection_t connection);

struct shmapper_connection_map_iter {
	struct shmap *shmap;
	struct shmap_map_iter iter;
};

struct shmapper_connection_map_iter_entry {
	const char __as_shared *connection;
	const struct shmapper_interface_set __as_shared *interfaces;
};

static inline shmapper_connection_t
shmapper_connection_map_iter_entry_key(struct shmap *shmap,
			       struct shmapper_connection_map_iter_entry *entry)
{
	return shmapper_connection(shmap_private(shmap, entry->connection));
}

struct shmapper_connection_map_iter
shmapper_connection_map_iter_init(struct shmap *shmap,
			 const struct shmapper_connection_map __as_shared *map);

void
shmapper_connection_map_iter_destroy(struct shmapper_connection_map_iter *iter);

bool
shmapper_connection_map_iter_has_next(struct shmapper_connection_map_iter *iter);

struct shmapper_connection_map_iter_entry
shmapper_connection_map_iter_next(struct shmapper_connection_map_iter *iter);

#define foreach_shmapper_connection(shmap, conns, entry) \
	for (struct shmapper_connection_map_iter iter __attribute__((cleanup(shmapper_connection_map_iter_destroy))) = shmapper_connection_map_iter_init(shmap, conns); \
	       shmapper_connection_map_iter_has_next(&iter) && (entry = shmapper_connection_map_iter_next(&iter)).interfaces;)
#endif
