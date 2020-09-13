// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2020,2021 IBM Corp.

#include "connection.h"
#include "interface.h"
#include "map.h"
#include "path.h"
#include "set.h"
#include "shmap.h"
#include "shmapper.h"
#include "subtree.h"

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

int shmapper_rdlock(struct shmapper *ctx)
{
	struct shmap_rwlock __as_private *rwlock;
	int rc;

	if ((rc = shmap_lock(ctx->shmap)))
		return rc;

	rwlock = &shmap_private(ctx->shmap, ctx->data)->rwlock;

	return shmap_rwlock_rdlock(ctx->shmap,
				   shmap_shared(ctx->shmap, rwlock));
}

int shmapper_wrlock(struct shmapper *ctx)
{
	struct shmap_rwlock __as_private *rwlock;
	int rc;

	if ((rc = shmap_lock(ctx->shmap)))
		return rc;

	rwlock = &shmap_private(ctx->shmap, ctx->data)->rwlock;

	return shmap_rwlock_wrlock(ctx->shmap,
				   shmap_shared(ctx->shmap, rwlock));
}

int shmapper_unlock(struct shmapper *ctx)
{
	struct shmap_rwlock __as_private *rwlock;
	int rc;

	rwlock = &shmap_private(ctx->shmap, ctx->data)->rwlock;

	if ((rc = shmap_rwlock_unlock(ctx->shmap,
				      shmap_shared(ctx->shmap, rwlock))))
		return rc;

	return shmap_unlock(ctx->shmap);
}

const struct shmapper_connection_map __as_shared *
shmapper_get_object(struct shmapper *ctx, shmapper_path_t path)
{
	return shmapper_path_map_get(ctx->shmap,
				    shmap_private(ctx->shmap, ctx->data)->paths,
				    path);
}

struct shmapper_subtree_iter
shmapper_get_subtree(struct shmapper *ctx, shmapper_path_t root)
{
	struct shmapper_subtree_iter iter;

	iter = shmapper_subtree_iter_init(ctx->shmap,
				   shmap_private(ctx->shmap, ctx->data)->paths,
				   root);

	return iter;
}

struct shmapper_subtree_iter
shmapper_get_subtree_paths(struct shmapper *ctx, shmapper_path_t root)
{
	return shmapper_get_subtree(ctx, root);
}

struct shmapper_ancestor_iter
shmapper_get_ancestors(struct shmapper *ctx, shmapper_path_t target)
{
	struct shmapper_ancestor_iter iter;

	shmapper_ancestor_iter_init(ctx->shmap,
				    shmap_private(ctx->shmap, ctx->data)->paths,
				    target, &iter);

	return iter;
}

static int shmapper_shmap_init(struct shmap *shmap, void __as_shared *user)
{
	struct shmapper_data __as_shared *data;
	int rc;

	data = user;

	if ((rc = shmap_lock(shmap)))
		return rc;

	/* FIXME: check return codes */
	shmap_mutex_init(shmap, shmap_ref(shmap, data, mutex));
	shmap_cond_init(shmap, shmap_ref(shmap, data, cond));
	shmap_private(shmap, data)->ready = false;
	shmap_private(shmap, data)->complete = false;

	shmap_rwlock_init(shmap, shmap_ref(shmap, data, rwlock));
	shmap_private(shmap, data)->paths = shmapper_path_map_init(shmap);

	if ((rc = shmap_unlock(shmap)))
		return rc;

	return 0;
}

static int shmapper_shmap_destroy(struct shmap *shmap, void __as_shared *user)
{
	struct shmapper_data __as_shared *data;
	int rc;

	data = user;

	if ((rc = shmap_lock(shmap)))
		return rc;

	/* FIXME: check return codes */
	shmapper_path_map_destroy(shmap, shmap_private(shmap, data)->paths);
	shmap_rwlock_destroy(shmap, shmap_ref(shmap, data, rwlock));

	shmap_cond_destroy(shmap, shmap_ref(shmap, data, cond));
	shmap_mutex_destroy(shmap, shmap_ref(shmap, data, mutex));

	if ((rc = shmap_unlock(shmap)))
		return rc;

	return 0;
}

int shmapper_init(struct shmapper *ctx, uint32_t flags)
{
	uint32_t shmap_flags = 0;

	if (flags & SHMAPPER_FLAG_DAEMON)
		shmap_flags |= SHMAP_FLAG_OWN;

	/* Make this interface less terrible */
	ctx->shmap = shmap_init(SHMAPPER_SONAME, shmap_flags,
				shmap_flags ? sizeof(*ctx->data) : 0,
				shmap_flags ? shmapper_shmap_init : NULL,
				shmapper_shmap_destroy);
	if (!ctx->shmap)
		return -ENOMEM;

	ctx->data = shmap_get_user(ctx->shmap);

	return 0;
}

void shmapper_destroy(struct shmapper *ctx)
{
	shmap_destroy(ctx->shmap);
}
