// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2020,2021 IBM Corp.

#include "shmapper.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

static int shmapper_client_wait_daemon_ready(struct shmapper *ctx)
{
	struct shmapper_data __as_shared *data;
	struct shmap *shmap;
	int rc, res;

	shmap = ctx->shmap;
	data = ctx->data;

	if ((rc = shmap_lock(shmap)) < 0)
		return rc;

	rc = shmap_mutex_lock(shmap, shmap_ref(shmap, data, mutex));
	if (rc < 0)
		goto release_shmap;

	if (!shmap_private(shmap, data)->ready) {
		fprintf(stderr, "Waiting for daemon to become ready\n");
		rc = shmap_cond_wait(shmap, shmap_ref(shmap, data, cond),
				     shmap_ref(shmap, data, mutex));
	}

	res = shmap_mutex_unlock(shmap, shmap_ref(shmap, data, mutex));
	if (res < 0) {
		fprintf(stderr, "Failed to release mutex: %d\n", res);
		rc = rc ?: res;
	}

release_shmap:
	if ((res = shmap_unlock(shmap)) < 0) {
		fprintf(stderr, "Failed to release shmap: %d\n", res);
		rc = rc ?: res;
	}

	return rc;
}

static int shmapper_client_mark_complete(struct shmapper *ctx)
{
	struct shmapper_data __as_shared *data;
	struct shmap *shmap;
	int rc, res;

	shmap = ctx->shmap;
	data = ctx->data;

	if ((rc = shmap_lock(shmap)) < 0)
		return rc;

	rc = shmap_mutex_lock(shmap, shmap_ref(shmap, data, mutex));
	if (rc < 0)
		goto release_shmap;

	shmap_private(shmap, data)->complete = true;

	shmap_cond_broadcast(shmap, shmap_ref(shmap, data, cond));

	rc = shmap_mutex_unlock(shmap, shmap_ref(shmap, data, mutex));
	if (rc < 0)
		fprintf(stderr, "Failed to release mutex\n");

release_shmap:
	if ((res = shmap_unlock(shmap)) < 0)
		rc = rc ?: res;

	return rc;
}

static int shmapper_client_query(struct shmapper *ctx, shmapper_path_t path)
{
	const struct shmapper_connection_map __as_shared *conns;
	struct shmapper_connection_map_iter_entry centry;
	struct shmap *shmap;
	int rc;

	shmap = ctx->shmap;

	if ((rc = shmapper_rdlock(ctx)))
		return rc;

	conns = shmapper_get_object(ctx, path);
	if (!conns) {
		fprintf(stderr, "Failed to find connection for path %s\n",
			path.path);
		goto release_shmapper;
	}

	foreach_shmapper_connection(shmap, conns, centry) {
		struct shmapper_interface_set_iter_entry ientry;
		shmapper_connection_t conn;

		conn = shmapper_connection_map_iter_entry_key(shmap, &centry);

		foreach_shmapper_interface(shmap, centry.interfaces, ientry) {
			printf("%s\t%s\t%s\n", path.path, conn.connection,
			       shmap_private(shmap, ientry.interface));
		}
	}

release_shmapper:
	return shmapper_unlock(ctx);
}

int main(int argc, const char *argv[])
{
	struct shmapper ctx;
	int rc, res;

	if (argc < 3)
		return EXIT_FAILURE;

	if (strcmp("get-object", argv[1]))
		return EXIT_FAILURE;

	if ((rc = shmapper_init(&ctx, SHMAPPER_FLAG_CLIENT)) < 0)
		return -rc;

	if ((rc = shmapper_client_wait_daemon_ready(&ctx)) < 0)
		goto cleanup_shmapper;

	if ((rc = shmapper_client_query(&ctx, shmapper_path(argv[2]))) < 0)
		fprintf(stderr, "Mapper query failed: %d\n", rc);

	if ((res = shmapper_client_mark_complete(&ctx)) < 0)
		rc = rc ?: res;

cleanup_shmapper:
	shmapper_destroy(&ctx);

	return -rc;
}

