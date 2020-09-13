// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2020,2021 IBM Corp.

#define _GNU_SOURCE
#include "../shmap.h"
#include "../vec.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <semaphore.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#define FUZZ_VEC_OP_IS_EMPTY	0
#define FUZZ_VEC_OP_SIZE	1
#define FUZZ_VEC_OP_GET		2
#define FUZZ_VEC_OP_INSERT	3
#define FUZZ_VEC_OP_REMOVE	4
#define FUZZ_VEC_OP_PUSH	5
#define FUZZ_VEC_OP_POP		6
#define FUZZ_VEC_OP_PEEK	7
#define FUZZ_VEC_OP_MAX		8

struct fuzz_vec_op {
	uint8_t op;
	size_t idx;
};

static int fuzz_vec_op_acquire(struct fuzz_vec_op *op)
{
	int fd = 0;
	int rc;

	if ((rc = read(fd, &op->op, sizeof(op->op)) != sizeof(op->op))) {
		fprintf(stderr, "Failed to read data for op of size %zuB\n",
			sizeof(op->op));
		return -ENODATA;
	}

	op->op %= FUZZ_VEC_OP_MAX;

	fprintf(stderr, "Got op %" PRIu8 "\n", op->op);

	if (!(op->op == FUZZ_VEC_OP_GET ||
			op->op == FUZZ_VEC_OP_INSERT ||
			op->op == FUZZ_VEC_OP_REMOVE))
		return 0;

	if ((rc = read(fd, &op->idx, sizeof(op->idx)) != sizeof(op->idx))) {
		fprintf(stderr, "Failed to read data for idx of size %zuB\n",
			sizeof(op->idx));
		return -ENODATA;
	}

	return 0;
}

static int fuzz_vec_op_exec(struct shmap *shmap,
			    struct shmap_vec __as_shared *vec,
			    const struct fuzz_vec_op *op)
{
	void __as_shared *dummy = (void __as_shared __force *)0x1234;
	void __as_shared *res;
	static size_t entries;
	int rc;

	if ((rc = shmap_lock(shmap)))
		return rc;

	switch (op->op) {
		case FUZZ_VEC_OP_IS_EMPTY:
			rc = shmap_vec_is_empty(shmap, vec);
			assert((entries && !rc) || (!entries && rc));
			break;
		case FUZZ_VEC_OP_SIZE:
			assert(entries == shmap_vec_size(shmap, vec));
			break;
		case FUZZ_VEC_OP_PUSH:
			rc = shmap_vec_push(shmap, vec, dummy);
			assert(!rc);
			assert(entries < SIZE_MAX);
			entries++;
			break;
		case FUZZ_VEC_OP_POP:
			res = shmap_vec_pop(shmap, vec);
			assert((entries && dummy == res) || !(entries || res));
			if (res) {
				assert(entries);
				entries--;
			}
			break;
		case FUZZ_VEC_OP_PEEK:
			res = shmap_vec_peek(shmap, vec);
			assert((entries && dummy == res) || !(entries || res));
			break;
		case FUZZ_VEC_OP_GET:
			res = shmap_vec_get(shmap, vec, op->idx);
			assert((entries > op->idx && dummy == res) ||
					(entries <= op->idx && !res));
			break;
		case FUZZ_VEC_OP_INSERT:
			rc = shmap_vec_insert(shmap, vec, dummy, op->idx);
			assert((op->idx <= entries && !rc) || rc < 0);
			entries += !rc;
			break;
		case FUZZ_VEC_OP_REMOVE:
			rc = shmap_vec_remove(shmap, vec, op->idx);
			assert((op->idx <= entries && !rc) || rc < 0);
			entries -= !rc;
			break;
	}

	if ((rc = shmap_unlock(shmap)))
		return rc;

	return 0;
}

int main(void)
{
	struct shmap_vec __as_shared *vec;
	struct fuzz_vec_op op;
	struct shmap *shmap;
	char *path;
	int res;
	int rc;

	/* Abstraction violation to clean up after previous runs */
	if (asprintf(&path, "/%s", SHMAPPER_SONAME) < 0)
		exit(EXIT_FAILURE);

	shm_unlink(path);
	sem_unlink(path);

	free(path);

	shmap = shmap_init(SHMAPPER_SONAME, SHMAP_FLAG_OWN, 0, NULL, NULL);
	if (!shmap) {
		fprintf(stderr, "Failed to initialise shmap\n");
		return ENODATA;
	}

	if ((rc = shmap_lock(shmap)))
		return rc;

	vec = shmap_vec_init(shmap, 0);

	if ((rc = shmap_unlock(shmap))) {
		res = rc;
		goto cleanup_vec;
	}

	if (!vec) {
		res = -ENOMEM;
		goto cleanup_shmap;
	}

	for (;;) {
		if ((res = fuzz_vec_op_acquire(&op))) {
			fprintf(stderr, "Failed to acquire fuzz data: %d\n",
				res);
			goto cleanup_vec;
		}

		if ((res = fuzz_vec_op_exec(shmap, vec, &op))) {
			fprintf(stderr, "Failed to execute fuzz op %u: %d\n",
				op.op, res);
			goto cleanup_vec;
		}
	}

cleanup_vec:
	if (vec) {
		if ((rc = shmap_lock(shmap)))
			goto cleanup_shmap;

		shmap_vec_destroy(shmap, vec);

		if ((rc = shmap_unlock(shmap)))
			goto cleanup_shmap;
	}

cleanup_shmap:
	shmap_destroy(shmap);

	return res;
}
