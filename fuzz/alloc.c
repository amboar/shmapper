// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2020,2021 IBM Corp.

#define _GNU_SOURCE
#ifdef NDEBUG
#undef NDEBUG
#endif

#include "../shmap.h"

#include <assert.h>
#include <endian.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <semaphore.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#define SHMAP_FUZZ_OP_FREE	0
#define SHMAP_FUZZ_OP_MALLOC	1
#define SHMAP_FUZZ_OP_REALLOC	2
#define SHMAP_FUZZ_OP_MAX	3

struct shmap_fuzz_op_malloc {
	uint8_t len;
	void *data;
	void __as_shared *ptr;
};

struct shmap_fuzz_op_free {
	uint8_t idx;
};

struct shmap_fuzz_op_realloc {
	uint8_t idx;
	uint8_t len;
	void *data;
};

struct shmap_fuzz_op {
	uint8_t op;
	union {
		struct shmap_fuzz_op_malloc malloc;
		struct shmap_fuzz_op_free free;
		struct shmap_fuzz_op_realloc realloc;
	};
};

struct shmap_fuzz_entry {
	struct shmap_fuzz_entry *next;
	struct shmap_fuzz_op_malloc op;
};

struct shmap_fuzz {
	struct shmap_fuzz_entry *start;
	struct shmap_fuzz_entry *end;
	size_t len;

	struct shmap *shmap;
};

static int shmap_fuzz_op_acquire_malloc(int fd, struct shmap_fuzz_op_malloc *op)
{
	int rc;

	if ((rc = read(fd, &op->len, sizeof(op->len)) != sizeof(op->len))) {
		fprintf(stderr, "Failed to read data for len of size %zuB\n",
			sizeof(op->len));
		return -ENODATA;
	}

	if (!op->len) {
		op->data = NULL;
		return 0;
	}

	op->data = malloc(op->len);
	if (!op->data)
		return -errno;

	if ((rc = read(fd, op->data, op->len)) != op->len) {
		fprintf(stderr, "Failed to read data for data of size %" PRIu8 "\n",
			op->len);
		free(op->data);
		return -ENODATA;
	}

	return 0;
}

static int shmap_fuzz_op_acquire_free(int fd, struct shmap_fuzz_op_free *op)
{
	int rc;

	if ((rc = read(fd, &op->idx, sizeof(op->idx)) != sizeof(op->idx))) {
		fprintf(stderr, "Failed to read data for len of size %zuB\n",
			sizeof(op->idx));
		return -ENODATA;
	}

	return 0;
}

static int shmap_fuzz_op_acquire_realloc(int fd,
					 struct shmap_fuzz_op_realloc *op)
{
	int rc;

	if ((rc = read(fd, &op->idx, sizeof(op->idx)) != sizeof(op->idx))) {
		fprintf(stderr, "Failed to read data for idx of size %zuB\n",
			sizeof(op->idx));
		return -ENODATA;
	}

	if ((rc = read(fd, &op->len, sizeof(op->len)) != sizeof(op->len))) {
		fprintf(stderr, "Failed to read data for len of size %zuB\n",
			sizeof(op->len));
		return -ENODATA;
	}

	op->data = malloc(op->len);
	if (!op->data)
		return -errno;

	if ((rc = read(fd, op->data, op->len)) != op->len) {
		fprintf(stderr, "Failed to read data for data of size %" PRIu8 "\n",
			op->len);
		free(op->data);
		return -ENODATA;
	}

	return 0;
}

static int shmap_fuzz_op_acquire(struct shmap_fuzz_op *op)
{
	int fd = 0;
	int rc;

	if ((rc = read(fd, &op->op, sizeof(op->op)) != sizeof(op->op))) {
		fprintf(stderr, "Failed to read data for op of size %zuB\n",
			sizeof(op->op));
		return -ENODATA;
	}

	op->op %= SHMAP_FUZZ_OP_MAX;

	switch (op->op) {
		case SHMAP_FUZZ_OP_MALLOC:
			return shmap_fuzz_op_acquire_malloc(fd, &op->malloc);
		case SHMAP_FUZZ_OP_FREE:
			return shmap_fuzz_op_acquire_free(fd, &op->free);
		case SHMAP_FUZZ_OP_REALLOC:
			return shmap_fuzz_op_acquire_realloc(fd, &op->realloc);
	}

	assert(false);
	return 0;
}

static void shmap_fuzz_add_entry(struct shmap_fuzz *fuzz,
				 struct shmap_fuzz_entry *entry)
{
	if (fuzz->end) {
		assert(fuzz->end->next == fuzz->start);
		fuzz->end->next = entry;
	}

	if (!fuzz->start)
		fuzz->start = entry;

	entry->next = fuzz->start;
	fuzz->end = entry;
	fuzz->len++;
}

static struct shmap_fuzz_entry *
shmap_fuzz_remove_entry(struct shmap_fuzz *fuzz, size_t idx)
{
	struct shmap_fuzz_entry *curr, *chosen;

	if (!fuzz->len)
		return NULL;

	idx %= fuzz->len;

	if (fuzz->start != fuzz->end) {
		curr = fuzz->start;
		while (idx) {
			curr = curr->next;
			assert(curr);
			idx--;
		}

		chosen = curr;
		assert(chosen);

		assert(fuzz->start);

		curr = fuzz->start;
		while (curr->next != chosen) {
			assert(curr);
			curr = curr->next;
		}

		if (fuzz->start == chosen) {
			fuzz->start = fuzz->start->next;
			fuzz->end->next = fuzz->start;
		}

		if (fuzz->end == chosen) {
			assert(chosen->next == fuzz->start);
			fuzz->end = curr;
		}

		curr->next = chosen->next;
	} else {
		chosen = fuzz->start;
		chosen->next = NULL;
		fuzz->start = NULL;
		fuzz->end = NULL;
	}

	fuzz->len--;

	return chosen;
}

static int shmap_fuzz_op_malloc(struct shmap_fuzz *fuzz,
				const struct shmap_fuzz_op_malloc *op)
{
	struct shmap_fuzz_entry *entry;
	int cleanup;
	int rc;

	if ((rc = shmap_lock(fuzz->shmap)))
		return rc;

	if (!op->len) {
		void __as_shared *ptr;

		if ((ptr = shmap_malloc(fuzz->shmap, op->len)))
			assert(false);

		goto cleanup_lock;
	}

	entry = malloc(sizeof(*entry));
	if (!entry) {
		perror("malloc");
		rc = -ENOMEM;
		goto cleanup_lock;
	}

	entry->op = *op;
	entry->op.ptr = shmap_malloc(fuzz->shmap, op->len);
	if (!entry->op.ptr) {
		fprintf(stderr, "shmap_alloc returned NULL\n");
		rc = -ENOMEM;
		free(entry);
		goto cleanup_lock;
	}

	memcpy(shmap_private(fuzz->shmap, entry->op.ptr), op->data, op->len);

	shmap_fuzz_add_entry(fuzz, entry);

	rc = 0;

cleanup_lock:
	if ((cleanup = shmap_unlock(fuzz->shmap)))
		fprintf(stderr, "Failed to release pool read lock: %d\n",
			cleanup);

	return rc;
}

static int shmap_fuzz_op_free(struct shmap_fuzz *fuzz,
			      const struct shmap_fuzz_op_free *op)
{
	struct shmap_fuzz_entry *chosen;
	uint8_t idx, offset;
	int rc;

	if (!fuzz->len)
		return 0;

	assert(fuzz->start);

	idx = op->idx % fuzz->len;
	offset = fuzz->len < UINT8_MAX ?
		(op->idx / (UINT8_MAX - fuzz->len)) % 7 : 0;

	chosen = shmap_fuzz_remove_entry(fuzz, idx);
	if (!chosen)
		return 0;

	if ((rc = shmap_lock(fuzz->shmap))) {
		fprintf(stderr, "Failed to acquire pool lock: %d\n", rc);
		return rc;
	}

	assert(!memcmp(shmap_private(fuzz->shmap, chosen->op.ptr),
		       chosen->op.data, chosen->op.len));

	/* Test that freeing a dud pointer doesn't crash us */
	shmap_free(fuzz->shmap,
			(void __as_shared *)
			(shmap_u_shared(chosen->op.ptr) + offset));
	/* If we passed a dud pointer, free the good pointer now */
	if (offset)
		shmap_free(fuzz->shmap, chosen->op.ptr);

	if ((rc = shmap_unlock(fuzz->shmap)))
		fprintf(stderr, "Failed to release pool read lock: %d\n", rc);

	free(chosen->op.data);
	free(chosen);

	return rc;
}

static int shmap_fuzz_op_realloc(struct shmap_fuzz *fuzz,
				 const struct shmap_fuzz_op_realloc *op)
{
	struct shmap_fuzz_entry *chosen;
	void __as_shared *adjusted;
	int rc;

	chosen = shmap_fuzz_remove_entry(fuzz, op->idx);
	if (!chosen)
		return 0;

	if ((rc = shmap_lock(fuzz->shmap))) {
		fprintf(stderr, "Failed to acquire pool lock: %d\n", rc);
		return rc;
	}

	/* Assert that the original data is intact */
	assert(!memcmp(shmap_private(fuzz->shmap, chosen->op.ptr),
		       chosen->op.data, chosen->op.len));

	/* Allocate our resized buffer */
	adjusted = shmap_realloc(fuzz->shmap, chosen->op.ptr, op->len);
	if (!op->len) {
		assert(!shmap_private(fuzz->shmap, adjusted));
		free(chosen->op.data);
		free(chosen);
		goto release_shmap;
	}

	assert(shmap_private(fuzz->shmap, adjusted));

	/* Assert that the old data appears in the resized buffer */
	assert(!memcmp(shmap_private(fuzz->shmap, adjusted),
		       chosen->op.data,
		       op->len < chosen->op.len ? op->len : chosen->op.len));

	/* Copy in our new data and reuse the entry */
	memcpy(shmap_private(fuzz->shmap, adjusted), op->data, op->len);
	chosen->op.ptr = adjusted;
	free(chosen->op.data);
	chosen->op.data = op->data;
	chosen->op.len = op->len;

	shmap_fuzz_add_entry(fuzz, chosen);

release_shmap:
	if ((rc = shmap_unlock(fuzz->shmap))) {
		fprintf(stderr, "Failed to release pool lock: %d\n", rc);
		return rc;
	}

	return 0;
}

static int shmap_fuzz_op_exec(struct shmap_fuzz *fuzz,
			      const struct shmap_fuzz_op *op)
{
	switch (op->op % SHMAP_FUZZ_OP_MAX) {
		case SHMAP_FUZZ_OP_FREE:
			return shmap_fuzz_op_free(fuzz, &op->free);
		case SHMAP_FUZZ_OP_MALLOC:
			return shmap_fuzz_op_malloc(fuzz, &op->malloc);
		case SHMAP_FUZZ_OP_REALLOC:
			return shmap_fuzz_op_realloc(fuzz, &op->realloc);
	}

	return 0;
}

int main(int argc, const char *argv[])
{
	struct shmap_fuzz fuzz = {NULL, NULL, 0, NULL};
	struct shmap_fuzz_op op;
	uint32_t flags;
	pid_t pid = 0;
	bool forever;
	int count;
	char *path;
	int rc;

	/* Abstraction violation to clean up after previous runs */
	if (asprintf(&path, "/%s", SHMAPPER_SONAME) < 0)
		exit(EXIT_FAILURE);

	shm_unlink(path);
	sem_unlink(path);

	free(path);

	forever = argc == 2;
	if (forever) {
		int rfd;

		count = atoi(argv[1]);

		if (count == 2) {
			if ((pid = fork()) < 0)
				return errno;

			if (pid)
				fprintf(stderr, "Spawned child %u from %u\n", pid, getpid());

			flags = pid ? SHMAP_FLAG_OWN : 0;
		} else if (count == 1) {
			flags = SHMAP_FLAG_OWN;
			pid = 0;
		} else {
			assert(false);
			abort();
		}

		if ((rfd = open("/dev/urandom", O_RDONLY)) < 0)
			return errno;

		if (dup2(rfd, 0) == -1)
			return errno;
	} else {
		flags = SHMAP_FLAG_OWN;
		count = 0;
		pid = 0;
	}

	fuzz.shmap = shmap_init(SHMAPPER_SONAME, flags, 0, NULL, NULL);
	if (!fuzz.shmap) {
		fprintf(stderr, "[%u] Failed to initialise mapper\n", getpid());
		return ENODATA;
	}

	for (;;) {
		if ((rc = shmap_fuzz_op_acquire(&op))) {
			fprintf(stderr, "Failed to acquire fuzz data: %d\n",
				rc);
			goto cleanup_shmap;
		}

		if ((rc = shmap_fuzz_op_exec(&fuzz, &op))) {
			fprintf(stderr,
				"Failed to execute fuzz op %u on data: %d\n",
				op.op % SHMAP_FUZZ_OP_MAX, rc);
			goto cleanup_shmap;
		}
	}

cleanup_shmap:
	shmap_destroy(fuzz.shmap);

	if (forever && count == 2 && pid) {
		int status;

		wait(&status);
		fprintf(stderr, "Child exited with status %d\n",
			WEXITSTATUS(status));

		return -rc ?: WEXITSTATUS(status);
	}

	return -rc;
}
