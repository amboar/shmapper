// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2020,2021 IBM Corp.

#define _GNU_SOURCE

#include "../hash.h"
#include "../set.h"
#include "../shmap.h"

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
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#if __SIZE_WIDTH__ == 64
#define sizetoh(x)	le64toh(x)
#elif __SIZE_WIDTH__ == 32
#define sizetoh(x)	le32toh(x)
#else
#error "Unsupported size_t width"
#endif

#define FUZZ_SET_OP_ADD		0
#define FUZZ_SET_OP_REMOVE	1
#define FUZZ_SET_OP_CONTAINS	2
#define FUZZ_SET_OP_MAX		3

struct fuzz_set_op_add {
	void *data;
	uint8_t len;
};

struct fuzz_set_op_remove {
	size_t idx;
};

struct fuzz_set_op_contains {
	bool indexed;
	union {
		struct {
			void *data;
			uint8_t len;
		} entry;
		size_t idx;
	};
};

struct fuzz_set_op {
	uint8_t op;
	union {
		struct fuzz_set_op_add add;
		struct fuzz_set_op_remove remove;
		struct fuzz_set_op_contains contains;
	};
};

struct fuzz_set_entry {
	struct fuzz_set_entry *next;
	void __as_shared *data;
	uint8_t len;
};

struct fuzz_set {
	struct fuzz_set_entry *start;
	struct fuzz_set_entry *end;
	size_t len;

	struct shmap *shmap;
	struct shmap_set __as_shared *set;
};

static int fuzz_set_op_acquire_add(int fd, struct fuzz_set_op_add *op)
{
	ssize_t rc;

	if ((rc = read(fd, &op->len, sizeof(op->len))) != sizeof(op->len)) {
		fprintf(stderr, "Failed to read data for len of size %zuB: %zd\n",
			sizeof(op->len), rc);
		return -ENODATA;
	}

	if (!(op->data = malloc(op->len))) {
		fprintf(stderr, "Failed to allocate data buffer of size %" PRIu8 "B\n",
			op->len);
		return -ENOMEM;
	}

	if ((rc = read(fd, op->data, op->len)) != op->len) {
		fprintf(stderr, "Failed to read data for size %" PRIu8 "B: %zd\n",
			op->len, rc);
		free(op->data);
		return -ENODATA;
	}

	return 0;
}

static int fuzz_set_op_acquire_remove(int fd, struct fuzz_set_op_remove *op)
{
	ssize_t rc;

	if ((rc = read(fd, &op->idx, sizeof(op->idx))) != sizeof(op->idx)) {
		fprintf(stderr, "Failed to read data for idx of size %zuB: %zd\n",
			sizeof(op->idx), rc);
		return -ENODATA;
	}

	op->idx = sizetoh(op->idx);

	return 0;
}

static int fuzz_set_op_acquire_contains(int fd, struct fuzz_set_op_contains *op)
{
	uint8_t indexed;
	ssize_t rc;

	if ((rc = read(fd, &indexed, sizeof(indexed))) != sizeof(indexed)) {
		fprintf(stderr, "Failed to read data for contained of size %zuB: %zd\n",
			sizeof(indexed), rc);
		return -ENODATA;
	}

	op->indexed = indexed & 1;

	if (op->indexed) {
		if ((rc = read(fd, &op->idx, sizeof(op->idx))) !=
				sizeof(op->idx)) {
			fprintf(stderr, "Failed ot read data for idx of size %zuB: %zd\n",
				sizeof(op->idx), rc);
			return -ENODATA;
		}

		op->idx = sizetoh(op->idx);

		return 0;
	}

	if ((rc = read(fd, &op->entry.len, sizeof(op->entry.len))) !=
			sizeof(op->entry.len)) {
		fprintf(stderr, "Failed to read data for len of size %zuB: %zd\n",
			sizeof(op->entry.len), rc);
		return -ENODATA;
	}

	if (!(op->entry.data = malloc(op->entry.len))) {
		fprintf(stderr, "Failed to allocate data buffer of size %" PRIu8 "B\n",
			op->entry.len);
		return -ENOMEM;
	}

	if ((rc = read(fd, op->entry.data, op->entry.len)) !=
			op->entry.len) {
		fprintf(stderr, "Failed to read data of size %" PRIu8 "B: %zd\n",
			op->entry.len, rc);
		free(op->entry.data);
		return -ENODATA;
	}

	return 0;
}

static int fuzz_set_op_acquire(struct fuzz_set_op *op)
{
	int fd = 0;
	int rc;

	if ((rc = read(fd, &op->op, sizeof(op->op))) != sizeof(op->op)) {
		fprintf(stderr, "Failed to read data for op of size %zuB\n",
			sizeof(op->op));
		return -ENODATA;
	}

	op->op %= FUZZ_SET_OP_MAX;

	switch (op->op) {
	case FUZZ_SET_OP_ADD:
		return fuzz_set_op_acquire_add(fd, &op->add);
	case FUZZ_SET_OP_REMOVE:
		return fuzz_set_op_acquire_remove(fd, &op->remove);
	case FUZZ_SET_OP_CONTAINS:
		return fuzz_set_op_acquire_contains(fd, &op->contains);
	}

	assert(false);
	return 0;
}

static uint32_t fuzz_set_hash(struct shmap *shmap, void __as_shared *obj,
			      size_t len)
{
	struct shmap_hash _hash, *hash = &_hash;

	shmap_hash_init(hash);
	shmap_hash_update(hash, shmap_private(shmap, obj), len);

	return shmap_hash_value(hash);
}

static int fuzz_set_op_exec(struct fuzz_set *fuzz, struct fuzz_set_op *op)
{
	int res = -EINVAL;
	int rc;

	printf("%s: op: %" PRIu8 "\n", __func__, op->op);

	if ((rc = shmap_lock(fuzz->shmap)))
		return rc;

	switch (op->op) {
		case FUZZ_SET_OP_ADD:
		{
			struct fuzz_set_entry *entry;

			if (!op->add.len)
				goto cleanup_shmap;

			entry = malloc(sizeof(*entry));
			if (!entry) {
				perror("malloc");
				res = -ENOMEM;
				goto cleanup_shmap;
			}

			entry->data = shmap_malloc(fuzz->shmap, op->add.len);
			if (!entry->data) {
				fprintf(stderr, "Failed to allocate shared memory\n");
				res = -ENOMEM;
				goto cleanup_entry;
			}

			memcpy(shmap_private(fuzz->shmap, entry->data),
			       op->add.data, op->add.len);

			entry->len = op->add.len;

			rc = shmap_set_contains(fuzz->shmap, fuzz->set,
					shmap_private(fuzz->shmap, entry->data),
					entry->len);
			if (rc < 0) {
				res = rc;
				goto cleanup_entry;
			}

			if (rc > 0) {
				res = 0;
				goto cleanup_entry;
			}

			/* Record the entry */
			if (!fuzz->start) {
				fuzz->start = entry;
				assert(!fuzz->end);
			}

			entry->next = fuzz->start;

			if (fuzz->end)
				fuzz->end->next = entry;

			fuzz->end = entry;
			fuzz->len++;

			fprintf(stderr, "Adding 0x%08" PRIx32 " to set\n",
				fuzz_set_hash(fuzz->shmap, entry->data,
					      entry->len));

			if ((res = shmap_set_add(fuzz->shmap, fuzz->set,
						 entry->data, entry->len)))
				goto cleanup_entry;

			rc = shmap_set_contains(fuzz->shmap, fuzz->set,
					shmap_private(fuzz->shmap, entry->data),
					entry->len);
			assert(rc > 0);

			free(op->add.data);
			op->add.len = 0;
			break;
cleanup_entry:
			free(entry);
			free(op->add.data);
			op->add.len = 0;
			break;
		}
		case FUZZ_SET_OP_REMOVE:
		{
			struct fuzz_set_entry *prev, *curr;
			size_t idx;

			prev = fuzz->end;
			curr = fuzz->start;
			if (!curr) {
				assert(!prev);
				assert(!fuzz->len);
				res = 0;
				goto cleanup_shmap;
			}

			assert(fuzz->len);
			idx = op->remove.idx % fuzz->len;
			while (idx) {
				idx--;
				prev = curr;
				curr = curr->next;
			}

			prev->next = curr->next;

			if (curr == fuzz->start && curr == fuzz->end) {
				assert(fuzz->len == 1);
				fuzz->start = fuzz->end = NULL;
			} else if (curr == fuzz->start) {
				fuzz->start = curr->next;
				fuzz->end->next = fuzz->start;
			} else if (curr == fuzz->end) {
				prev->next = fuzz->start;
				fuzz->end = prev;
			}

			fuzz->len--;

			fprintf(stderr, "Removing 0x%08" PRIx32 " from set\n",
				fuzz_set_hash(fuzz->shmap, curr->data,
					      curr->len));

			if ((res = shmap_set_remove(fuzz->shmap, fuzz->set,
					shmap_private(fuzz->shmap, curr->data),
					curr->len)) < 0)
				goto cleanup_curr;

			rc = shmap_set_contains(fuzz->shmap, fuzz->set,
					shmap_private(fuzz->shmap, curr->data),
					curr->len);
			assert(rc == 0);
cleanup_curr:
			shmap_free(fuzz->shmap, curr->data);
			free(curr);
			break;
		}
		case FUZZ_SET_OP_CONTAINS:
		{
			void __as_shared *data;
			size_t len;

			if (op->contains.indexed) {
				struct fuzz_set_entry *curr;
				size_t idx;

				curr = fuzz->start;
				if (!curr) {
					assert(!fuzz->len);
					res = 0;
					goto cleanup_shmap;
				}

				idx = op->contains.idx % fuzz->len;
				while (idx) {
					idx--;
					curr = curr->next;
				}

				data = curr->data;
				len = curr->len;
			} else {
				if (!op->contains.entry.len)
					goto cleanup_shmap;

				data = shmap_malloc(fuzz->shmap,
						    op->contains.entry.len);
				if (!data) {
					fprintf(stderr, "Failed to allocate shared memory\n");
					res = -ENOMEM;
					goto cleanup_shmap;
				}

				memcpy(shmap_private(fuzz->shmap, data),
				       op->contains.entry.data,
				       op->contains.entry.len);
				len = op->contains.entry.len;
			}

			fprintf(stderr, "Testing set for 0x%08" PRIx32 "\n",
				fuzz_set_hash(fuzz->shmap, data, len));

			res = shmap_set_contains(fuzz->shmap, fuzz->set,
					shmap_private(fuzz->shmap, data), len);

			if (op->contains.indexed)
				assert(res == 1);

			res = 0;

			if (!op->contains.indexed) {
				shmap_free(fuzz->shmap, data);
				free(op->contains.entry.data);
				op->contains.entry.len = 0;
			}

			break;
		}
	}

cleanup_shmap:
	if ((rc = shmap_unlock(fuzz->shmap)))
		return rc;

	return res;
}

int main(void)
{
	struct fuzz_set fuzz = {NULL, NULL, 0, NULL, NULL};
	struct fuzz_set_op op;
	char *path;
	int res;
	int rc;

	/* Abstraction violation to clean up after previous runs */
	if (asprintf(&path, "/%s", SHMAPPER_SONAME) < 0)
		exit(EXIT_FAILURE);

	shm_unlink(path);
	sem_unlink(path);

	free(path);

	fuzz.shmap = shmap_init(SHMAPPER_SONAME, SHMAP_FLAG_OWN, 0, NULL, NULL);
	if (!fuzz.shmap) {
		fprintf(stderr, "Failed to initialise shmap\n");
		return ENODATA;
	}

	if ((rc = shmap_lock(fuzz.shmap)))
		return rc;

	fuzz.set = shmap_set_init(fuzz.shmap);

	if ((rc = shmap_unlock(fuzz.shmap))) {
		res = rc;
		goto cleanup_set;
	}

	if (!fuzz.set) {
		res = -ENOMEM;
		goto cleanup_shmap;
	}

	for (;;) {
		if ((res = fuzz_set_op_acquire(&op))) {
			fprintf(stderr, "Failed to acquire fuzz data: %d\n",
				res);
			goto cleanup_set;
		}

		if ((res = fuzz_set_op_exec(&fuzz, &op))) {
			fprintf(stderr, "Failed to execute set op %u: %d\n",
				op.op, res);
			goto cleanup_set;
		}
	}

cleanup_set:
	if (fuzz.set) {
		if ((rc = shmap_lock(fuzz.shmap)))
			goto cleanup_shmap;

		shmap_set_destroy(fuzz.shmap, fuzz.set);

		if ((rc = shmap_unlock(fuzz.shmap)))
			goto cleanup_shmap;
	}

cleanup_shmap:
	shmap_destroy(fuzz.shmap);

	return 0;
}
