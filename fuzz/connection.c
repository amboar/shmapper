// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2020,2021 IBM Corp.

#define _GNU_SOURCE

#include "../connection.h"

#include <assert.h>
#include <endian.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <semaphore.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#define FUZZ_CONNECTION_OP_ADD		0
#define FUZZ_CONNECTION_OP_REMOVE	1
#define FUZZ_CONNECTION_OP_GET		2
#define FUZZ_CONNECTION_OP_ADD_IFACE	3
#define FUZZ_CONNECTION_OP_REMOVE_IFACE	4
#define FUZZ_CONNECTION_OP_DESTROY	5
#define FUZZ_CONNECTION_OP_MAX		6

struct fuzz_connection_op_add {
	char *data;
};

struct fuzz_connection_op_remove {
	uint64_t idx;
};

struct fuzz_connection_op_get {
	bool indexed;
	union {
		char *data;
		uint64_t idx;
	};
};

struct fuzz_connection_op {
	uint8_t op;
	union {
		struct fuzz_connection_op_add add;
		struct fuzz_connection_op_remove remove;
		struct fuzz_connection_op_get contains;
	};
};

struct fuzz_connection_entry {
	struct fuzz_connection_entry *next;
	char *data;
	struct shmapper_interface_set __as_shared *set;
};

struct fuzz_connection {
	struct shmap *shmap;
	struct shmapper_connection_map __as_shared *map;

	struct fuzz_connection_entry *start;
	size_t len;
};

static void asciify(char *data, size_t len)
{
	size_t i;

	assert(len < SIZE_MAX);

	for (i = 0; i < len; i++) {
		unsigned char c = data[i];

		c %= 26;
		c += 'a';

		data[i] = c;
	}
}

static int
fuzz_connection_op_acquire_add(int fd, struct fuzz_connection_op_add *op)
{
	uint8_t len;
	ssize_t rc;

	if ((rc = read(fd, &len, sizeof(len))) != sizeof(len)) {
		fprintf(stderr,
			"Failed to read data for len of size %zuB: %zd\n",
			sizeof(len), rc);
		return -ENODATA;
	}

	if (!(op->data = malloc(len + 1))) {
		fprintf(stderr,
			"Failed to allocate data buffer of size %" PRIu8 "B\n",
			len);
		return -ENOMEM;
	}

	if ((rc = read(fd, op->data, len)) != len) {
		fprintf(stderr,
			"Failed to read data for size %" PRIu8 "B: %zd\n",
			len, rc);
		free(op->data);
		return -ENODATA;
	}

	op->data[len] = '\0';

	asciify(op->data, len);

	return 0;
}

static int
fuzz_connection_op_acquire_remove(int fd, struct fuzz_connection_op_remove *op)
{
	ssize_t rc;

	if ((rc = read(fd, &op->idx, sizeof(op->idx))) != sizeof(op->idx)) {
		fprintf(stderr, "Failed to read data for idx of size %zuB: %zd\n",
			sizeof(op->idx), rc);
		return -ENODATA;
	}

	op->idx = le64toh(op->idx);

	return 0;
}

static int
fuzz_connection_op_acquire_get(int fd,
				   struct fuzz_connection_op_get *op)
{
	uint8_t indexed;
	uint8_t len;
	ssize_t rc;

	rc = read(fd, &indexed, sizeof(indexed));
	if (rc != sizeof(op->indexed)) {
		fprintf(stderr, "Failed to read data for idx of size %zuB: %zd\n",
			sizeof(op->idx), rc);
		return -ENODATA;
	}

	op->indexed = indexed & 1;

	if (op->indexed) {
		rc = read(fd, &op->idx, sizeof(op->idx));
		if (rc != sizeof(op->idx)) {
			fprintf(stderr,
				"Failed to read data for idx of size %zuB: %zd\n",
				sizeof(op->idx), rc);
			return -ENODATA;
		}

		op->idx = le64toh(op->idx);

		return 0;
	}

	rc = read(fd, &len, sizeof(len));
	if (rc != sizeof(len)) {
		fprintf(stderr,
			"Failed to read data for idx of size %zuB: %zd\n",
			sizeof(op->idx), rc);
		return -ENODATA;
	}

	if (!(op->data = malloc(len + 1))) {
		fprintf(stderr,
			"Failed to allocate data buffer of size %" PRIu8 "B\n",
			len);
		return -ENOMEM;
	}

	if ((rc = read(fd, op->data, len)) != len) {
		fprintf(stderr,
			"Failed to read data of size %" PRIu8 "B: %zd\n",
			len, rc);
		free(op->data);
		return -ENODATA;
	}

	op->data[len] = '\0';

	asciify(op->data, len);

	return 0;
}

static int fuzz_connection_op_acquire(struct fuzz_connection_op *op)
{
	int fd = 0;
	int rc;

	if ((rc = read(fd, &op->op, sizeof(op->op))) != sizeof(op->op)) {
		fprintf(stderr, "Failed to read data for op of size %zuB\n",
			sizeof(op->op));
		return -ENODATA;
	}

	op->op %= FUZZ_CONNECTION_OP_MAX;

	switch (op->op) {
	case FUZZ_CONNECTION_OP_ADD:
		return fuzz_connection_op_acquire_add(fd, &op->add);
	case FUZZ_CONNECTION_OP_REMOVE:
		return fuzz_connection_op_acquire_remove(fd, &op->remove);
	case FUZZ_CONNECTION_OP_GET:
		return fuzz_connection_op_acquire_get(fd, &op->contains);
	case FUZZ_CONNECTION_OP_DESTROY:
		break;
	}

	return 0;
}

static int fuzz_connection_op_exec(struct fuzz_connection *fuzz,
				  struct fuzz_connection_op *op)
{
	int rc, res;

	if ((rc = shmap_lock(fuzz->shmap)))
		return rc;

	switch (op->op) {
	case FUZZ_CONNECTION_OP_ADD:
	{
		struct shmapper_interface_set __as_shared *set;
		struct fuzz_connection_entry *entry;
		bool contains;

		if (!op->add.data)
			goto cleanup_shmap;

		printf("add: '%s'\n", op->add.data);

		contains = shmapper_connection_map_get(fuzz->shmap,
					     fuzz->map,
					     shmapper_connection(op->add.data));
		if (contains) {
			rc = 0;
			goto cleanup_add_data;
		}

		set = shmapper_interface_set_init(fuzz->shmap);
		if (!set) {
			rc = -ENOMEM;
			goto cleanup_add_data;
		}

		rc = shmapper_connection_map_add(fuzz->shmap, fuzz->map,
					      shmapper_connection(op->add.data),
					      set);

		if (rc)
			goto cleanup_set;

		entry = malloc(sizeof(*entry));
		if (!entry) {
			perror("malloc");
			free(op->add.data);
			rc = -ENOMEM;
			goto cleanup_set;
		}

		entry->data = op->add.data;
		entry->set = set;
		entry->next = fuzz->start;

		fuzz->start = entry;
		fuzz->len++;

		break;

cleanup_set:
		shmap_free(fuzz->shmap, set);

cleanup_add_data:
		free(op->add.data);
		break;
	}
	case FUZZ_CONNECTION_OP_REMOVE:
	{
		struct fuzz_connection_entry *prev, *curr;
		void __as_shared *set;
		size_t idx;

		curr = fuzz->start;
		if (!curr) {
			assert(!fuzz->len);
			rc = 0;
			goto cleanup_shmap;
		}

		assert(fuzz->len);
		idx = op->remove.idx % fuzz->len;
		while (idx) {
			idx--;
			prev = curr;
			curr = curr->next;
		}


		if (curr == fuzz->start)
			fuzz->start = curr->next;
		else
			prev->next = curr->next;

		fuzz->len--;

		printf("remove: '%s'\n", curr->data);

		set = shmapper_connection_map_remove(fuzz->shmap, fuzz->map,
				shmapper_connection(curr->data));

		assert(set);

		shmapper_interface_set_destroy(fuzz->shmap, curr->set);
		free(curr->data);
		free(curr);

		break;
	}
	case FUZZ_CONNECTION_OP_GET:
	{
		const struct shmapper_interface_set __as_shared *set;
		const char *data;

		if (op->contains.indexed) {
			struct fuzz_connection_entry *curr;
			size_t idx;

			curr = fuzz->start;
			if (!curr) {
				assert(!fuzz->len);
				res = 0;
				goto cleanup_shmap;
			}

			assert(fuzz->len);
			idx = op->contains.idx % fuzz->len;

			while (idx--)
				curr = curr->next;

			assert(curr);

			data = curr->data;
		} else {
			data = op->contains.data;
		}

		printf("get: '%s'\n", data);
		set = shmapper_connection_map_get(fuzz->shmap, fuzz->map,
						  shmapper_connection(data));

		data = NULL;

		if (op->contains.indexed)
			assert(set);
		else
			free(op->contains.data);

		rc = 0;

		break;

	}
	case FUZZ_CONNECTION_OP_DESTROY:
	{
		struct fuzz_connection_entry *curr;

		printf("destroy\n");

		while ((curr = fuzz->start)) {
			fuzz->start = curr->next;
			free(curr->data);
			free(curr);
			fuzz->len--;
		}

		assert(!fuzz->len);

		shmapper_connection_map_destroy(fuzz->shmap, fuzz->map);
		fuzz->map = shmapper_connection_map_init(fuzz->shmap);

		break;
	}
	}

cleanup_shmap:
	if ((res = shmap_unlock(fuzz->shmap)))
		rc = rc ?: res;

	return rc;
}

int main(void)
{
	struct fuzz_connection_entry *curr;
	struct fuzz_connection fuzz = {0};
	struct fuzz_connection_op op;
	char *path;
	int res;
	int rc;

	if (asprintf(&path, "/%s", SHMAPPER_SONAME) < 0)
		exit(EXIT_FAILURE);

	shm_unlink(path);
	sem_unlink(path);

	free(path);

	fuzz.shmap = shmap_init(SHMAPPER_SONAME, SHMAP_FLAG_OWN, 0, NULL, NULL);
	if (!fuzz.shmap)
		exit(EXIT_FAILURE);

	if ((rc = shmap_lock(fuzz.shmap)))
		goto cleanup_shmap;

	fuzz.map = shmapper_connection_map_init(fuzz.shmap);
	if (!fuzz.map) {
		rc = -ENOMEM;
		goto release_shmap;
	}

	rc = shmap_unlock(fuzz.shmap);
	assert(!rc);

	for (;;) {
		if ((rc = fuzz_connection_op_acquire(&op))) {
			fprintf(stderr, "Failed to acquire fuzz data: %d\n",
				rc);
			goto cleanup_map;
		}

		if ((rc = fuzz_connection_op_exec(&fuzz, &op))) {
			fprintf(stderr, "Failed to execute set op %u: %d\n",
				op.op, rc);

			while ((curr = fuzz.start)) {
				fuzz.start = curr->next;
				free(curr->data);
				free(curr);
				fuzz.len--;
			}

			goto cleanup_map;
		}
	}

cleanup_map:
	if ((rc = shmap_lock(fuzz.shmap)))
		goto cleanup_shmap;

	shmapper_connection_map_destroy(fuzz.shmap, fuzz.map);

release_shmap:
	if ((res = shmap_unlock(fuzz.shmap)))
		rc = rc ?: res;

cleanup_shmap:
	shmap_destroy(fuzz.shmap);

	while ((curr = fuzz.start)) {
		fuzz.start = curr->next;
		free(curr->data);
		free(curr);
		fuzz.len--;
	}

	return -rc;
}
