// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2020,2021 IBM Corp.

#include "introspect.h"
#include "shmapper.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

static int shmapper_daemon_mark_ready(struct shmapper *ctx)
{
	struct shmapper_data __as_shared *data;
	struct shmap *shmap;
	int rc, res;

	shmap = ctx->shmap;
	data = ctx->data;

	if ((rc = shmap_lock(shmap)))
		return rc;
	
	if ((rc = shmap_mutex_lock(shmap, shmap_ref(shmap, data, mutex))) < 0)
		goto release_shmap;

	shmap_private(shmap, data)->ready = true;

	rc = shmap_cond_broadcast(shmap, shmap_ref(shmap, data, cond));
	if (rc < 0)
		fprintf(stderr, "Failed to broadcast condition: %d\n", rc);

	res = shmap_mutex_unlock(shmap, shmap_ref(shmap, data, mutex));
	if (res < 0) {
		fprintf(stderr, "Failed to release mutex: %d\n", rc);
		rc = rc ?: res;
	}

release_shmap:
	if ((res = shmap_unlock(shmap))) {
		fprintf(stderr, "Failed to release shmap lock: %d\n", res);
		rc = rc ?: res;
	}

	return rc;
}

static int shmapper_daemon_wait_client_complete(struct shmapper *ctx)
{
	struct shmapper_data __as_shared *data;
	struct shmap *shmap;
	int rc, res;

	shmap = ctx->shmap;
	data = ctx->data;

	if ((rc = shmap_lock(shmap)))
		return rc;

	
	if ((rc = shmap_mutex_lock(shmap, shmap_ref(shmap, data, mutex))) < 0)
		goto release_shmap;

	if (!shmap_private(shmap, data)->complete) {
		fprintf(stderr, "Waiting for client to complete\n");
		rc = shmap_cond_wait(shmap, shmap_ref(shmap, data, cond),
				     shmap_ref(shmap, data, mutex));
	}

	rc = shmap_mutex_unlock(shmap, shmap_ref(shmap, data, mutex));
	if (rc < 0)
		fprintf(stderr, "Failed to release mutex\n");

release_shmap:
	if ((res = shmap_unlock(shmap))) {
		fprintf(stderr, "Failed to release shmap lock\n");
		rc = rc ?: res;
	}

	return rc;
}

static int shmapper_daemon(void)
{
	struct shmapper _shmapper, *shmapper = &_shmapper;
	char **connections;
	sd_bus *bus;
	int rc;
	int i;

	rc = shmapper_init(shmapper, SHMAPPER_FLAG_DAEMON);
	if (rc < 0)
		return -rc;

        /* Connect to the system bus */
        rc = sd_bus_open_system(&bus);
        if (rc < 0) {
                fprintf(stderr, "Failed to connect to system bus: %s\n",
			strerror(-rc));
                goto cleanup_shmapper;
        }

	connections = introspect_list_connections(bus);
	if (!connections)
		goto cleanup_bus;

	for (i = 0; connections[i] && !rc; i++) {
		printf("Introspecting connection %s\n", connections[i]);
		rc = introspect_connection(bus,
					   shmapper_connection(connections[i]),
					   shmapper);
		if (rc)
			printf("Introspection failed: %s\n", strerror(-rc));

		if (rc == -EACCES)
			rc = 0;
	}

	for (i = 0; connections[i]; i++)
		free(connections[i]);
	free(connections);

	if (rc < 0)
		goto cleanup_bus;

	rc = shmapper_daemon_mark_ready(shmapper);
	if (rc < 0)
		goto cleanup_bus;

	rc = shmapper_daemon_wait_client_complete(shmapper);

cleanup_bus:
	sd_bus_unref(bus);

cleanup_shmapper:
	shmapper_destroy(shmapper);

	return -rc;

}

int main(void)
{
	return shmapper_daemon();
}
