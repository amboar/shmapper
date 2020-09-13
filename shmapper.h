/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2020,2021 IBM Corp. */

#ifndef SHMAPPER_H
#define SHMAPPER_H

#include "ancestor.h"
#include "connection.h"
#include "path.h"
#include "subtree.h"

struct shmapper_data {
	struct shmap_mutex mutex;
	struct shmap_cond cond;
	bool ready;
	bool complete;

	struct shmap_rwlock rwlock;
	struct shmapper_path_map __as_shared *paths;
};

struct shmapper {
	struct shmap *shmap;
	struct shmapper_data __as_shared *data;
};

#define SHMAPPER_FLAG_CLIENT	0
#define SHMAPPER_FLAG_DAEMON	1

int shmapper_init(struct shmapper *ctx, uint32_t flags);
void shmapper_destroy(struct shmapper *ctx);

int shmapper_rdlock(struct shmapper *ctx);
int shmapper_wrlock(struct shmapper *ctx);
int shmapper_unlock(struct shmapper *ctx);

const struct shmapper_connection_map __as_shared *
shmapper_get_object(struct shmapper *ctx, shmapper_path_t path);

struct shmapper_subtree_iter
shmapper_get_subtree(struct shmapper *ctx, shmapper_path_t root);

struct shmapper_subtree_iter
shmapper_get_subtree_paths(struct shmapper *ctx, shmapper_path_t root);

struct shmapper_ancestor_iter
shmapper_get_ancestors(struct shmapper *ctx, shmapper_path_t target);

#endif
