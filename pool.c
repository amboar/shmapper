// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2020,2021 IBM Corp.

#define _GNU_SOURCE
#include "align.h"
#include "alloc.h"
#include "pool.h"
#include "shmap.h"
#include "trace.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define SHMAP_POOL_MAGIC 0x73686d70

static int shmap_pool_init_owned(struct shmap_pool *pool, size_t min_len)
{
	pthread_rwlockattr_t attr;
	int rc;

	/* Create the shared memory */
	if ((rc = shm_open(pool->path, O_RDWR | O_CREAT, 0666)) < 0) {
		shmap_err("Failed to open shm: %d\n", -errno);
		return -errno;
	}

	pool->shm = rc;
	shmap_trace("Created shm at %s\n", pool->path);

	/* Expand shared memory to accommodate pool metadata */
	if ((rc = ftruncate(pool->shm, min_len))) {
		rc = -errno;
		shmap_err("Failed to resize mapping to %zuB: %d\n",
			  min_len, rc);
		goto cleanup_shm;
	}

	shmap_trace("Resized pool to %zu\n", min_len);

	/* Map the shared memory into the process' address space */
	pool->base = mmap(NULL, min_len, PROT_READ | PROT_WRITE,
			  MAP_SHARED_VALIDATE, pool->shm, 0);
	if ((void __force *)pool->base == MAP_FAILED) {
		rc = -errno;
		shmap_err("Failed to map shm: %d\n", rc);
		goto cleanup_shm;
	}

	shmap_trace("Mapped pool to %p for %zu\n", pool->base, min_len);

	pool->base->magic = SHMAP_POOL_MAGIC;

	/* Initialise the pool */
	if ((rc = -pthread_rwlockattr_init(&attr))) {
		shmap_err("Failed to initialise rwlock attributes: %d\n", rc);
		goto cleanup_map;
	}

	if ((rc = -pthread_rwlockattr_setpshared(&attr,
						 PTHREAD_PROCESS_SHARED))) {
		shmap_err("Failed to set pshared state of rwlock: %d\n", rc);
		goto cleanup_rwlockattr;
	}

	if ((rc = -pthread_rwlock_init(&pool->base->lock, &attr))) {
		shmap_err("Failed to init rwlock: %d\n", rc);
		goto cleanup_rwlockattr;
	}

	pthread_rwlockattr_destroy(&attr);

	pool->base->len = min_len;
	pool->base->refs = 1;
	pool->len = min_len;

	shmap_trace("Pool initialised\n");

	return 0;

cleanup_rwlockattr:
	pthread_rwlockattr_destroy(&attr);

cleanup_map:
	if (munmap(pool->base, min_len))
		shmap_err("Failed to unmap shm: %d\n", -errno);
cleanup_shm:
	if (shm_unlink(pool->path))
		shmap_err("Failed to unlink shm: %d\n", -errno);

	if (close(pool->shm))
		shmap_err("Failed to close shm: %d\n", -errno);

	return rc;
}

static int shmap_pool_init_borrowed(struct shmap_pool *pool, size_t min_len)
{
	int rc;

	/* Open the shared memory, fail if it doesn't exist */
	if ((rc = shm_open(pool->path, O_RDWR, 0666)) < 0) {
		shmap_err("Failed to open shm: %d\n", -errno);
		return -errno;
	}

	pool->shm = rc;
	shmap_trace("Opened shm at %s\n", pool->path);

	/*
	 * Map the shared memory into the process' address space so we can
	 * access refs and rwlock
	 */
	pool->base = mmap(NULL, min_len, PROT_READ | PROT_WRITE,
			  MAP_SHARED_VALIDATE, pool->shm, 0);
	if (pool->base == MAP_FAILED) {
		rc = -errno;
		shmap_err("Failed to map shm: %d\n", rc);
		goto cleanup_shm;
	}

	pool->len = min_len;

	if (!pool->base->refs) {
		rc = -ENOMEM;
		shmap_err("shm destroyed before we initalised\n");
		goto cleanup_shm;
	}

	/* We're a new user, so increment the reference count */
	pool->base->refs++;

	shmap_trace("Mapped shm at %p for %zu\n", pool->base, min_len);

	/* TODO: Consider consolidating this with shmap_pool_read_lock() */
	if ((rc = -pthread_rwlock_rdlock(&pool->base->lock))) {
		shmap_err("Failed to acquire write lock: %d\n", rc);
		return rc;
	}

	if (pool->len != pool->base->len) {
		void *base;

		base = mremap(pool->base, pool->len, pool->base->len,
			      MREMAP_MAYMOVE);
		if (base == MAP_FAILED) {
			rc = -errno;
			shmap_err("Failed to remap shm: %d\n", rc);
			goto cleanup_shm;
		}

		pool->base = base;
		pool->len = pool->base->len;

		shmap_trace("Remapped shm at %p for %zu\n",
			    pool->base, pool->len);
	}

	if ((rc = -pthread_rwlock_unlock(&pool->base->lock))) {
		shmap_err("Failed to release read lock: %d\n", rc);
		assert(false);
		return rc;
	}

	return 0;

cleanup_shm:
	if (close(pool->shm))
		shmap_err("Failed to close shm: %d\n", -errno);

	return rc;
}

#define shmap_pool_p_shared(_pool, _target) \
	shmap_p_shared((_pool)->base, _target)

static void __as_shared *shmap_pool_op_xlate_private(void *ctx,
						     void __as_private *ptr)
{
	struct shmap_pool *pool = ctx;
	void __as_shared *xlated;

	assert(pool->base->magic == SHMAP_POOL_MAGIC);

	if (!ptr)
		return NULL;

	xlated = shmap_pool_p_shared(pool, ptr);

	return xlated;
}

#define shmap_pool_p_private(_pool, _target) \
	shmap_p_private((_pool)->base, _target)

static void __as_private *shmap_pool_op_xlate_shared(void *ctx,
						     void __as_shared *ptr)
{
	struct shmap_pool *pool = ctx;
	void __as_private *xlated;

	assert(pool->base->magic == SHMAP_POOL_MAGIC);

	if (!ptr)
		return NULL;

	xlated = shmap_pool_p_private(pool, ptr);

	return xlated;
}

static int shmap_pool_op_contains(void *ctx, void *base, size_t len)
{
	struct shmap_pool *pool = ctx;

	return shmap_pool_contains(pool, base, len);
}

static ssize_t shmap_pool_op_grow(void *ctx, intptr_t grow, void **allocated)
{
	struct shmap_pool *pool = ctx;

	return shmap_pool_grow(pool, grow, allocated);
}

static const struct shmap_alloc_pool_ops pool_ops = {
	.xlate_private = shmap_pool_op_xlate_private,
	.xlate_shared = shmap_pool_op_xlate_shared,
	.contains = shmap_pool_op_contains,
	.grow = shmap_pool_op_grow,
};

int shmap_pool_init(struct shmap_pool *pool, const char *path, uint32_t flags)
{
	size_t min_len;
	bool owned;
	int rc;

	min_len = sysconf(_SC_PAGESIZE);

	pool->flags = flags;
	pool->path = path;

	owned = flags & SHMAP_FLAG_OWN;

	shmap_trace("Initialising pool as %s\n", owned ? "owner" : "borrower");

	if (owned) {
		if ((rc = shmap_pool_init_owned(pool, min_len)))
			return rc;

		pool->alloc = shmap_alloc_init_ops(&pool_ops, pool,
						pool->base->data,
				   		pool->len - sizeof(*pool->base),
						flags);
		if (!pool->alloc) {
			shmap_err("Failed to initialise allocator\n");
			goto cleanup_pool;
		}
	} else {
		shmap_trace("Initialisating borrowed pool\n");

		if ((rc = shmap_pool_init_borrowed(pool, min_len)))
			return rc;

		shmap_trace("Completed pool initialisation, initalising allocator\n");

		if ((rc = shmap_pool_read_lock(pool)))
			goto cleanup_pool;

		pool->alloc = shmap_alloc_init_ops(&pool_ops, pool,
				   		pool->base->data,
				   		pool->len - sizeof(*pool->base),
						flags);

		if ((rc = shmap_pool_read_unlock(pool)))
			goto cleanup_alloc;

		if (!pool->alloc)
			goto cleanup_pool;
	}

	return 0;

cleanup_alloc:
	if (pool->alloc)
		shmap_alloc_destroy(pool->alloc);

cleanup_pool:
	shmap_pool_destroy(pool);

	return rc;
}

int shmap_pool_destroy(struct shmap_pool *pool)
{
	int refs;
	int rc;

	if (!pool)
		return -EINVAL;

	if (pool->alloc)
		shmap_alloc_destroy(pool->alloc);

	pool->alloc = NULL;

	pool->base->refs--;
	refs = !!pool->base->refs;

	if (pool->base->refs == 0) {
		if (shm_unlink(pool->path))
			shmap_err("Failed to unlink shm: %d\n", -errno);

		shmap_trace("Destroying rwlock\n");
		if ((rc = -pthread_rwlock_destroy(&pool->base->lock)))
			shmap_err("Failed to destroy rwlock: %d\n", rc);
	}

	if (pool->base) {
		shmap_trace("Unmapping shm at %p for %zuB\n",
			    pool->base, pool->base->len);
		if (munmap(pool->base, pool->base->len))
			shmap_err("Failed to unmap shm: %d\n", -errno);
	}

	if (close(pool->shm))
		shmap_err("Failed to close shm: %d\n", -errno);

	return refs;
}

static int __shmap_pool_brk(struct shmap_pool *pool, void *brk)
{
	size_t want;
	void *got;

	if (brk < (void *)pool->base->data) {
		shmap_err("brk value %p will corrupt pool metadata below %p\n",
			    brk, pool->base->data);
		return -EINVAL;
	}

	want = (uintptr_t)brk - (uintptr_t)pool->base;

	if (ftruncate(pool->shm, want)) {
		shmap_err("ftruncate to %zuB failed: %d\n", want, -errno);
		return -errno;
	}

	shmap_trace("Remapping shm for %zu\n", want);

	got = mremap(pool->base, pool->len, want, MREMAP_MAYMOVE);
	if (got == MAP_FAILED) {
		pid_t cpid = getpid();
		int rc, maperr;
		char *cmd;

		maperr = -errno;

		shmap_err("Remap failed: %d\n", maperr);

		if (asprintf(&cmd, "cat /proc/%u/maps", cpid) < 0)
			return -errno;

		rc = system(cmd);
		free(cmd);
		if (rc < 0)
			perror("system");

		return maperr;
	}

	shmap_trace("shm now mapped at %p for %zuB\n", got, want);

	pool->base = got;
	pool->base->len = want;
	pool->len = want;

	return 0;
}

int shmap_pool_contains(struct shmap_pool *pool, void *base, size_t len)
{
	uintptr_t beyond;

	assert(pool->base->magic == SHMAP_POOL_MAGIC);

	if ((uintptr_t)base + len < (uintptr_t)base)
		return -EINVAL;

	if ((uintptr_t)base < (uintptr_t)pool->base)
		return -EINVAL;

	beyond = (uintptr_t)pool->base + pool->base->len;

	assert(beyond > (uintptr_t)pool->base);

	return (uintptr_t)base < beyond && (uintptr_t)base + len <= beyond;
}

ssize_t shmap_pool_grow(struct shmap_pool *pool, intptr_t grow,
			void **allocated)
{
	size_t have;
	size_t want;
	int cleanup;
	ssize_t rc;
	void *brk;

	assert(pool);
	assert(grow);

	assert(pool->base->magic == SHMAP_POOL_MAGIC);

	if (grow < 0) {
		/* Only support positive growth for now */
		shmap_err("You need to implement support for shrinking\n");
		return -EINVAL;
	}

	if ((pool->base->len + (uintptr_t)grow) < pool->base->len) {
		shmap_err("Requested for growth %lu overflows\n",
			  (uintptr_t)grow);
		return -EINVAL;
	}

	/* Use the current pool length to catch concurrent resizes */
	have = pool->base->len;

	if ((rc = shmap_pool_read_unlock(pool))) {
		shmap_err("Failed to drop read lock: %zd\n", rc);
		assert(false);
		return rc;
	}

	if ((rc = -pthread_rwlock_wrlock(&pool->base->lock))) {
		shmap_err("Failed to acquire write lock: %zd\n", rc);
		return rc;
	}

	/* Test whether a concurrent resize occurred */
	if (have != pool->base->len) {
		/* If so, the caller should rescan the free list */
		rc = -EAGAIN;
		goto cleanup_locks;
	}

	want = align_up(pool->base->len + grow, sysconf(_SC_PAGESIZE));

	shmap_trace("Expanding shm to %zuB\n", want);

	rc = __shmap_pool_brk(pool, (void *)((uintptr_t)pool->base + want));
	brk = (void *)((uintptr_t)pool->base + have);

	if (rc) {
		shmap_err("Operation failed: %zd\n", rc);
		brk = NULL;
	}

	*allocated = brk;
	rc = want - have;

cleanup_locks:
	if ((cleanup = -pthread_rwlock_unlock(&pool->base->lock))) {
		shmap_err("Failed to unlock: %d\n", cleanup);
		assert(false);
		return cleanup;
	}

	if ((cleanup = shmap_pool_read_lock(pool))) {
		shmap_err("Failed to acquire read lock: %d\n", cleanup);
		return cleanup;
	}

	return rc;
}

/* Post-conditions:
 *	- Pool lock is held
 * 	- All pool pointers are valid
 */
int shmap_pool_read_lock(struct shmap_pool *pool)
{
	void *got;
	int rc;

	assert(pool);
	assert(pool->base->magic == SHMAP_POOL_MAGIC);

	if ((rc = -pthread_rwlock_rdlock(&pool->base->lock))) {
		shmap_err("Failed to acquire pool read lock: %d\n", rc);
		return rc;
	}

	/* Fast-path: Pool size has not changed */
	if (pool->len == pool->base->len)
		return 0;

	/* Expand the mapping */
	shmap_trace("Expanding shm map from %zu to %zu\n", pool->len,
		     pool->base->len);

	assert(pool->len < pool->base->len);
	got = mremap(pool->base, pool->len, pool->base->len, MREMAP_MAYMOVE);
	if (got == MAP_FAILED) {
		shmap_err("Failed to expand mapping to %zu: %d\n",
			    pool->base->len, -errno);
		if ((rc = -pthread_rwlock_unlock(&pool->base->lock)))
			shmap_err("Failed to unlock: %d\n", rc);
		return -errno;
	}

	pool->base = got;
	pool->len = pool->base->len;

	shmap_trace("Remapped shm at %p for %zu\n",
		    pool->base, pool->base->len);

	shmap_alloc_remap(pool->alloc, (void *)pool->base->data);

	return 0;
}

int shmap_pool_read_unlock(struct shmap_pool *pool)
{
	int rc;

	assert(pool);
	assert(pool->base->magic == SHMAP_POOL_MAGIC);

	if ((rc = -pthread_rwlock_unlock(&pool->base->lock))) {
		shmap_trace("Failed to release pool read lock: %d\n", rc);
		return rc;
	}

	return 0;
}
