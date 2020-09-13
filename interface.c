// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2020,2021 IBM Corp.

#include "interface.h"

#include <errno.h>
#include <string.h>

struct shmapper_interface_set {
	struct shmap_set __as_shared *interfaces;
};

struct shmapper_interface_set __as_shared *
shmapper_interface_set_init(struct shmap *shmap)
{
	struct shmapper_interface_set __as_shared *set;
	struct shmap_set __as_shared *interfaces;

	/* TODO: Optimise memory use, wrt allocator overhead */

	set = shmap_malloc(shmap, sizeof(*set));
	if (!set)
		goto err;

	interfaces = shmap_set_init(shmap);
	if (!interfaces)
		goto cleanup_set;

	shmap_private(shmap, set)->interfaces = interfaces;

	return set;

cleanup_set:
	shmap_free(shmap, set);
err:
	return NULL;
}

static void
shmapper_interface_set_clear(struct shmap *shmap,
			     struct shmapper_interface_set __as_shared *set)
{
	struct shmapper_interface_set_iter _iter, *iter = &_iter;

	_iter = shmapper_interface_set_iter_init(shmap, set);

	while (shmapper_interface_set_iter_has_next(iter)) {
		struct shmapper_interface_set_iter_entry entry;
		shmapper_interface_t iface;

		entry = shmapper_interface_set_iter_next(iter);
		iface = shmapper_interface(shmap_private(shmap,
							 entry.interface));

		shmapper_interface_set_remove(shmap, set, iface);
	}

	shmapper_interface_set_iter_destroy(iter);
}

void
shmapper_interface_set_destroy(struct shmap *shmap,
			       struct shmapper_interface_set __as_shared *set)
{
	shmapper_interface_set_clear(shmap, set);
	shmap_set_destroy(shmap, shmap_private(shmap, set)->interfaces);
	shmap_free(shmap, set);
}

int shmapper_interface_set_add(struct shmap *shmap,
			       struct shmapper_interface_set __as_shared *set,
			       const shmapper_interface_t interface)
{
	char __as_shared *shared;
	int rc;

	if (shmap_set_contains(shmap, shmap_private(shmap, set)->interfaces,
			       interface.interface,
			       strlen(interface.interface) + 1))
		return 0;

	shared = shmap_strdup(shmap, interface.interface);
	if (!shared)
		return -ENOMEM;

	rc = shmap_set_add(shmap, shmap_private(shmap, set)->interfaces,
			   shared, strlen(interface.interface) + 1);

	if (rc)
		shmap_free(shmap, shared);

	return rc;
}

int
shmapper_interface_set_remove(struct shmap *shmap,
			      struct shmapper_interface_set __as_shared *set,
			      const shmapper_interface_t interface)
{
	char __as_shared *key;
	int rc;

	key = shmap_set_get(shmap, shmap_private(shmap, set)->interfaces,
			    interface.interface,
			    strlen(interface.interface) + 1);
	if (!key)
		return 0;

	rc = shmap_set_remove(shmap, shmap_private(shmap, set)->interfaces,
			      interface.interface,
			      strlen(interface.interface) + 1);

	assert(!rc);

	shmap_free(shmap, key);

	return rc;
}

bool
shmapper_interface_set_contains(struct shmap *shmap,
			   const struct shmapper_interface_set __as_shared *set,
			   const shmapper_interface_t interface)
{
	return shmap_set_contains(shmap, shmap_private(shmap, set)->interfaces,
				  interface.interface,
				  strlen(interface.interface) + 1);
}

struct shmapper_interface_set_iter
shmapper_interface_set_iter_init(struct shmap *shmap,
			   const struct shmapper_interface_set __as_shared *set)
{
	struct shmapper_interface_set_iter iter;

	shmap_set_iter_init(shmap, shmap_private(shmap, set)->interfaces,
			    &iter.iter);
	iter.shmap = shmap;

	return iter;
}

void
shmapper_interface_set_iter_destroy(struct shmapper_interface_set_iter *iter)
{
	shmap_set_iter_destroy(iter->shmap, &iter->iter);
}

bool
shmapper_interface_set_iter_has_next(struct shmapper_interface_set_iter *iter)
{
	return shmap_set_iter_has_next(iter->shmap, &iter->iter);
}

struct shmapper_interface_set_iter_entry
shmapper_interface_set_iter_next(struct shmapper_interface_set_iter *iter)
{
	struct shmapper_interface_set_iter_entry ientry;
	struct shmap_set_iter_entry entry;

	entry = shmap_set_iter_next(iter->shmap, &iter->iter);

	ientry.interface = entry.key;

	return ientry;
}
