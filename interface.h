/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2020,2021 IBM Corp. */

#ifndef SHMAPPER_INTERFACE_H
#define SHMAPPER_INTERFACE_H

#include "set.h"
#include "shmap.h"

#include <stdbool.h>

typedef struct {
	const char *interface;
} shmapper_interface_t;
#define shmapper_interface(x)	((shmapper_interface_t){x})

struct shmapper_interface_set;

struct shmapper_interface_set __as_shared *
shmapper_interface_set_init(struct shmap *shmap);

void
shmapper_interface_set_destroy(struct shmap *shmap,
			       struct shmapper_interface_set __as_shared *set);

int shmapper_interface_set_add(struct shmap *shmap,
			       struct shmapper_interface_set __as_shared *set,
			       const shmapper_interface_t interface);

int
shmapper_interface_set_remove(struct shmap *shmap,
			      struct shmapper_interface_set __as_shared *set,
			      const shmapper_interface_t interface);

bool
shmapper_interface_set_contains(struct shmap *shmap,
			   const struct shmapper_interface_set __as_shared *set,
			   const shmapper_interface_t interface);

struct shmapper_interface_set_iter {
	struct shmap *shmap;
	struct shmap_set_iter iter;
};

struct shmapper_interface_set_iter_entry {
	const char __as_shared *interface;
};

struct shmapper_interface_set_iter
shmapper_interface_set_iter_init(struct shmap *shmap,
			  const struct shmapper_interface_set __as_shared *set);

void
shmapper_interface_set_iter_destroy(struct shmapper_interface_set_iter *iter);

bool
shmapper_interface_set_iter_has_next(struct shmapper_interface_set_iter *iter);

struct shmapper_interface_set_iter_entry
shmapper_interface_set_iter_next(struct shmapper_interface_set_iter *iter);

#define foreach_shmapper_interface(shmap, ifaces, entry) \
	for (struct shmapper_interface_set_iter iter __attribute__((cleanup(shmapper_interface_set_iter_destroy))) = shmapper_interface_set_iter_init(shmap, ifaces); \
		shmapper_interface_set_iter_has_next(&iter) &&  (entry = shmapper_interface_set_iter_next(&iter)).interface;)
#endif
