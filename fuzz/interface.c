// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2020,2021 IBM Corp.

#define _GNU_SOURCE

#include "../interface.h"

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

#define FUZZ_INTERFACE_OP_ADD		0
#define FUZZ_INTERFACE_OP_REMOVE	1
#define FUZZ_INTERFACE_OP_CONTAINS	2
#define FUZZ_INTERFACE_OP_DESTROY	3
#define FUZZ_INTERFACE_OP_MAX		4

struct fuzz_interface_op_add {
	char *data;
};

struct fuzz_interface_op_remove {
	uint64_t idx;
};

struct fuzz_interface_op_contains {
	bool indexed;
	union {
		char *data;
		uint64_t idx;
	};
};

struct fuzz_interface_op {
	uint8_t op;
	union {
		struct fuzz_interface_op_add add;
		struct fuzz_interface_op_remove remove;
		struct fuzz_interface_op_contains contains;
	};
};

struct fuzz_interface_entry {
	struct fuzz_interface_entry *next;
	char *data;
};

struct fuzz_interface {
	struct shmap *shmap;
	struct shmapper_interface_set __as_shared *set;

	struct fuzz_interface_entry *start;
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
fuzz_interface_op_acquire_add(int fd, struct fuzz_interface_op_add *op)
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
fuzz_interface_op_acquire_remove(int fd, struct fuzz_interface_op_remove *op)
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
fuzz_interface_op_acquire_contains(int fd,
				   struct fuzz_interface_op_contains *op)
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

static int fuzz_interface_op_acquire(struct fuzz_interface_op *op)
{
	int fd = 0;
	int rc;

	if ((rc = read(fd, &op->op, sizeof(op->op))) != sizeof(op->op)) {
		fprintf(stderr, "Failed to read data for op of size %zuB\n",
			sizeof(op->op));
		return -ENODATA;
	}

	op->op %= FUZZ_INTERFACE_OP_MAX;

	switch (op->op) {
	case FUZZ_INTERFACE_OP_ADD:
		return fuzz_interface_op_acquire_add(fd, &op->add);
	case FUZZ_INTERFACE_OP_REMOVE:
		return fuzz_interface_op_acquire_remove(fd, &op->remove);
	case FUZZ_INTERFACE_OP_CONTAINS:
		return fuzz_interface_op_acquire_contains(fd, &op->contains);
	case FUZZ_INTERFACE_OP_DESTROY:
		break;
	}

	return 0;
}

static int fuzz_interface_op_exec(struct fuzz_interface *fuzz,
				  struct fuzz_interface_op *op)
{
	int rc, res;

	if ((rc = shmap_lock(fuzz->shmap)))
		return rc;

	switch (op->op) {
	case FUZZ_INTERFACE_OP_ADD:
	{
		struct fuzz_interface_entry *entry;
		bool contains;

		if (!op->add.data)
			goto cleanup_shmap;


		contains = shmapper_interface_set_contains(fuzz->shmap,
					      fuzz->set,
					      shmapper_interface(op->add.data));
		if (contains) {
			rc = 0;
			goto cleanup_add_data;
		}

		rc = shmapper_interface_set_add(fuzz->shmap, fuzz->set,
					      shmapper_interface(op->add.data));

		if (rc)
			goto cleanup_add_data;

		entry = malloc(sizeof(*entry));
		if (!entry) {
			perror("malloc");
			free(op->add.data);
			rc = -ENOMEM;
			goto cleanup_shmap;
		}

		entry->data = op->add.data;
		entry->next = fuzz->start;

		fuzz->start = entry;
		fuzz->len++;

		break;

cleanup_add_data:
		free(op->add.data);
		break;
	}
	case FUZZ_INTERFACE_OP_REMOVE:
	{
		struct fuzz_interface_entry *prev, *curr;
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

		rc = shmapper_interface_set_remove(fuzz->shmap, fuzz->set,
				shmapper_interface(curr->data));

		assert(!rc);

		free(curr->data);
		free(curr);

		break;
	}
	case FUZZ_INTERFACE_OP_CONTAINS:
	{
		const char *data;

		if (op->contains.indexed) {
			struct fuzz_interface_entry *curr;
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

		rc = shmapper_interface_set_contains(fuzz->shmap, fuzz->set,
				shmapper_interface(data));

		data = NULL;

		if (op->contains.indexed)
			assert(rc);
		else
			free(op->contains.data);

		rc = 0;

		break;

	}
	case FUZZ_INTERFACE_OP_DESTROY:
	{
		struct fuzz_interface_entry *curr;

		while ((curr = fuzz->start)) {
			fuzz->start = curr->next;
			free(curr->data);
			free(curr);
			fuzz->len--;
		}

		assert(!fuzz->len);

		shmapper_interface_set_destroy(fuzz->shmap, fuzz->set);
		fuzz->set = shmapper_interface_set_init(fuzz->shmap);

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
	struct fuzz_interface_entry *curr;
	struct fuzz_interface fuzz = {0};
	struct fuzz_interface_op op;
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

	fuzz.set = shmapper_interface_set_init(fuzz.shmap);
	if (!fuzz.set) {
		rc = -ENOMEM;
		goto release_shmap;
	}

	rc = shmap_unlock(fuzz.shmap);
	assert(!rc);

	for (;;) {
		if ((rc = fuzz_interface_op_acquire(&op))) {
			fprintf(stderr, "Failed to acquire fuzz data: %d\n",
				rc);
			goto cleanup_set;
		}

		if ((rc = fuzz_interface_op_exec(&fuzz, &op))) {
			fprintf(stderr, "Failed to execute set op %u: %d\n",
				op.op, rc);

			while ((curr = fuzz.start)) {
				fuzz.start = curr->next;
				free(curr->data);
				free(curr);
				fuzz.len--;
			}

			goto cleanup_set;
		}
	}

cleanup_set:
	if ((rc = shmap_lock(fuzz.shmap)))
		goto cleanup_shmap;

	shmapper_interface_set_destroy(fuzz.shmap, fuzz.set);

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
