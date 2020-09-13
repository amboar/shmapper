// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2020,2021 IBM Corp.

#define _GNU_SOURCE
#include "alloc.h"
#include "shmap.h"
#include "trace.h"

#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdalign.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#define container_of(ptr, type, member) (ptr - offsetof(type, member))

#define SHMAP_ALLOC_MAGIC 0x73686d70

#define SHMAP_ALLOC_COALESCE	1

enum shmap_alloc_state { shmap_alloc_s_allocated, shmap_alloc_s_free };

struct shmap_alloc_region {
	uint32_t magic;

	/* Modified under lock, ordered for packing purposes */
	enum shmap_alloc_state state;
	struct shmap_alloc_region __as_shared *next_free;
	size_t len;
	pthread_mutex_t lock;

	char data[] __attribute__((aligned(8)));
};

/* Lives in the shared region */
struct shmap_alloc_pool {
	/*
	 * The shared address space is relative to the address of
	 * shmap_alloc_pool. To distinguish a NULL shared pointer from a
	 * pointer to the anchor free block below, add a sentinel member.
	 */
	const uint64_t null;

	/* User data pointer */
	void __as_shared *user;

	/*
	 * Point to a fixed, zero-sized anchor region. As such the pointer
	 * access needs no lock.
	 */
	struct shmap_alloc_region __as_shared *free;
};

#define to_shmap_alloc_region(ptr) \
	container_of(ptr, struct shmap_alloc_region, data)

static uintptr_t align_up(uintptr_t ptr, uintptr_t align)
{
	assert(ptr + align > ptr);
	return (ptr + align - 1) & ~(align - 1);
}

static size_t shmap_alloc_region_size(size_t want)
{
	return align_up(sizeof(struct shmap_alloc_region) + want,
			alignof(struct shmap_alloc_region));
}

static struct shmap_alloc_region __as_private *
shmap_alloc_region_next(struct shmap_alloc *alloc,
			 struct shmap_alloc_region __as_private *region)
{
	struct shmap_alloc_region __as_private *next;
	size_t len;
	int rc;

	assert(region->magic == SHMAP_ALLOC_MAGIC);

	len = shmap_alloc_region_size(region->len);
	next = (void __as_private *)(shmap_u_private(region) + len);
	rc = alloc->ops.contains(alloc->ctx, next, 0);
	if (rc < 0) {
		shmap_err("Bad contains query for %p: %d",
			  shmap_alloc_to_shared(alloc, next), rc);
		assert(rc >= 0);
		return NULL;
	} else if (rc) {
		shmap_trace("Region after %p (%zuB: %zuB, %zuB, %zuB) is %p\n",
			    shmap_alloc_to_shared(alloc, region),
			    len,
			    sizeof(*region),
			    shmap_alloc_region_size(0),
			    region->len,
			    shmap_alloc_to_shared(alloc, next));
		return next;
	}

	shmap_trace("Region after %p (%zuB) at %p exceeds pool size\n",
		    shmap_alloc_to_shared(alloc, region), len,
		    shmap_alloc_to_shared(alloc, next));
	return NULL;
}

static int
region_mutex_init(struct shmap_alloc_region __as_private *region)
{
	pthread_mutexattr_t attr;
	int rc;

	if ((rc = -pthread_mutexattr_init(&attr)))
		return rc;

	if ((rc = -pthread_mutexattr_setpshared(&attr, PTHREAD_PROCESS_SHARED)))
		return rc;

	if ((rc = -pthread_mutex_init(&region->lock, &attr)))
		return rc;

	if ((rc = -pthread_mutexattr_destroy(&attr)))
		return rc;

	return 0;
}

static int
region_mutex_destroy(struct shmap_alloc_region __as_private *region)
{
	return -pthread_mutex_destroy(&region->lock);
}

static int
region_mutex_lock(struct shmap_alloc_region __as_private *region)
{
	return -pthread_mutex_lock(&region->lock);
}

static int
region_mutex_trylock(struct shmap_alloc_region __as_private *region)
{
	return -pthread_mutex_trylock(&region->lock);
}

static int
region_mutex_unlock(struct shmap_alloc_region __as_private *region)
{
	return -pthread_mutex_unlock(&region->lock);
}

static int
shmap_alloc_region_init(struct shmap_alloc *alloc,
			struct shmap_alloc_region __as_private *region,
			size_t size)
{
	int rc;

	if ((rc = region_mutex_init(region)))
		return rc;

	region->next_free = NULL;
	region->state = shmap_alloc_s_allocated;
	region->len = size;
	region->magic = SHMAP_ALLOC_MAGIC;

#ifdef NTRACE
	(void)alloc;
#else
	{
	void __as_private *end;

	end = (void*)((uintptr_t)region + shmap_alloc_region_size(size));

	shmap_trace("Initialised region @ %p for %zuB (%zuB) ending at %p\n",
		    shmap_alloc_to_shared(alloc, region),
		    size,
		    shmap_alloc_region_size(size),
		    shmap_alloc_to_shared(alloc, end));
	}
#endif

	return 0;
}

static struct shmap_alloc_region *
shmap_alloc_region_split(struct shmap_alloc *alloc,
			 struct shmap_alloc_region *curr,
			 size_t size)
{
	struct shmap_alloc_region *next;
	size_t next_off;
	size_t len;

	if (size > curr->len)
		return NULL;

	if (curr->len <= (align_up(size, alignof(typeof(*curr)))
				+ sizeof(*curr)))
		return NULL;

	next_off = shmap_alloc_region_size(size);
	next = (struct shmap_alloc_region *)((uintptr_t)curr + next_off);
	len = shmap_alloc_region_size(curr->len) -
		next_off - shmap_alloc_region_size(0);
	if (shmap_alloc_region_init(alloc, next, len))
		return NULL;
	curr->len = size;

	return next;
}

void shmap_alloc_remap(struct shmap_alloc *alloc, void *base)
{
	alloc->pool = base;
}

static int shmap_alloc_region_allocate(struct shmap_alloc *alloc,
				       intptr_t increment,
				       struct shmap_alloc_region **region)
{
	void __as_shared *pool;
	void *allocated;
	ssize_t got;
	size_t need;
	int rc;

	assert(region && !(*region));

	need = shmap_alloc_region_size(increment);

	/*
	 * The mapping may move as part of expansion. Translate the pool
	 * pointer to a shared value that we can translate back after the remap
	 * completes.
	 *
	 * Use the pool's translations because we're moving our reference point.
	 */
	pool = alloc->ops.xlate_private(alloc->ctx, alloc->pool);

	/* Now that we have a shared pool pointer, try our expansion */
	got = alloc->ops.grow(alloc->ctx, need, &allocated);
	if (got < 0)
		return got;

	/*
	 * Retranslate the shared pool pointer back to a private for our own
	 * use.
	 */
	alloc->pool = alloc->ops.xlate_shared(alloc->ctx, pool);

	assert(allocated);
	*region = allocated;

	/* Initialise a region covering the newly available memory */
	got -= shmap_alloc_region_size(0);
	if ((rc = shmap_alloc_region_init(alloc, *region, got))) {
		shmap_err("Failed to initialise the new region: %d\n", rc);
		*region = NULL;
		return rc;
	}

	return 0;
}

static struct shmap_alloc_region __as_private *
shmap_alloc_take_free(struct shmap_alloc *alloc, size_t size)
{
	struct shmap_alloc_region __as_private *curr;
	struct shmap_alloc_region __as_private *prev;
	int rc;

	prev = NULL;
	curr = shmap_alloc_to_private(alloc, alloc->pool->free);

again:
	shmap_trace("prev: %p, curr: %p, want: %zuB, have: %zuB\n",
		    shmap_alloc_to_shared(alloc, prev),
		    shmap_alloc_to_shared(alloc, curr),
		    size, curr ? curr->len : 0);

	/* Have we run out of free regions? */

	if (!curr) {
		assert(prev);
		assert(prev->magic == SHMAP_ALLOC_MAGIC);
		if ((rc = region_mutex_unlock(prev)))
			shmap_trace("Failed to unlock prev region %p: %d\n",
				    shmap_alloc_to_shared(alloc, prev), rc);
		shmap_trace("Search for region of %zuB ended in NULL sentinel\n",
			    size);

		return NULL;
	}

	/* We have a free region in curr, lock it to assess suitability */

	assert(curr->magic == SHMAP_ALLOC_MAGIC);
	if ((rc = region_mutex_lock(curr))) {
		shmap_trace("Failed to lock curr region %p: %d\n",
			    shmap_alloc_to_shared(alloc, curr), rc);

		if (!prev)
			return NULL;

		if ((rc = region_mutex_unlock(prev)))
			shmap_trace("Failed to unlock prev region %p: %d\n",
				    shmap_alloc_to_shared(alloc, prev), rc);

		return NULL;
	}

	/* Is the current region suitable for allocation? */

	/*
	 * Note: Blocks in the free list may transiently appear as allocated as
	 * part of coalescing adjacent regions in the free path. Skip any such
	 * regions.
	 */
	if (curr->len < size || curr->state != shmap_alloc_s_free) {

		/* Current region is unsuitable, so try the next free region */

		if (prev) {
			assert(prev->magic == SHMAP_ALLOC_MAGIC);
			if ((rc = region_mutex_unlock(prev))) {
				shmap_trace("Failed to unlock prev region %p: %d\n",
					    shmap_alloc_to_shared(alloc, prev),
					    rc);
				return NULL;
			}
		}

		prev = curr;
		curr = shmap_alloc_to_private(alloc, curr->next_free);
		goto again;
	}

	/* The current region is suitable, so allocate it */

	if (prev)
		prev->next_free = curr->next_free;

	curr->state = shmap_alloc_s_allocated;

	/*
	 * As the current region is now allocated we have exclusive access, so
	 * drop the lock
	 */

	if ((rc = region_mutex_unlock(curr))) {
		shmap_trace("Failed to unlock curr at %p: %d\n",
			    shmap_alloc_to_shared(alloc, curr), rc);
		curr = NULL;
	}

	if (prev) {
		assert(prev->magic == SHMAP_ALLOC_MAGIC);
		if ((rc = region_mutex_unlock(prev))) {
			shmap_trace("Failed to unlock prev at %p: %d\n",
				    shmap_alloc_to_shared(alloc, prev), rc);
			curr = NULL;
		}
	}

	return curr;
}

static void shmap_alloc_add_free(struct shmap_alloc *alloc,
				  struct shmap_alloc_region __as_private *add)
{
	struct shmap_alloc_region __as_private *prev;
	struct shmap_alloc_region __as_private *curr;
	int rc;

	prev = NULL;
	curr = shmap_alloc_to_private(alloc, alloc->pool->free);

again:
	shmap_trace("prev: %p, curr: %p, add: %p, of: %zuB\n",
		    shmap_alloc_to_shared(alloc, prev),
		    shmap_alloc_to_shared(alloc, curr),
		    shmap_alloc_to_shared(alloc, add),
		    add->len);

	/* Have we run out of free regions? */

	if (!curr) {
		assert(prev);
		assert(prev->magic == SHMAP_ALLOC_MAGIC);

		prev->next_free = shmap_alloc_to_shared(alloc, add);
		add->next_free = NULL;
		add->state = shmap_alloc_s_free;

		if ((rc = region_mutex_unlock(prev)))
			shmap_err("Failed to release prev lock on %p: %d\n",
				  shmap_alloc_to_shared(alloc, prev), rc);

		return;
	}

	/* We have a free region in curr, lock it to assess suitability */

	assert(curr->magic == SHMAP_ALLOC_MAGIC);
	if ((rc = region_mutex_lock(curr))) {
		shmap_err("Failed to acquire curr lock on %p: %d\n",
			  shmap_alloc_to_shared(alloc, prev), rc);

		if (!prev)
			return;

		if ((rc = region_mutex_unlock(prev)))
			shmap_trace("Failed to unlock prev region %p: %d\n",
				    shmap_alloc_to_shared(alloc, prev), rc);

		return;
	}

	/* Should we insert the new free region after the current region? */

	/*
	 * Blocks in the free list may transiently appear as allocated as part
	 * of coalescing adjacent regions in the free path. Skip any such
	 * regions.
	 */
	if (add->len > curr->len || curr->state != shmap_alloc_s_free) {

		/* Current region is unsuitable, so try the next free region */

		if (prev) {
			assert(prev->magic == SHMAP_ALLOC_MAGIC);
			if ((rc = region_mutex_unlock(prev))) {
				shmap_err("Failed to release prev lock on %p: %d\n",
					  shmap_alloc_to_shared(alloc, prev),
					  rc);
				return;
			}
		}

		prev = curr;
		curr = shmap_alloc_to_private(alloc, curr->next_free);
		goto again;
	}

	/* The current region is suitable, insert new free region before it */

	add->next_free = shmap_alloc_to_shared(alloc, curr);
	add->state = shmap_alloc_s_free;

	assert(curr->magic == SHMAP_ALLOC_MAGIC);
	if ((rc = region_mutex_unlock(curr)))
		shmap_err("Failed to release curr lock on %p: %d\n",
			  shmap_alloc_to_shared(alloc, curr), rc);

	/* Update the previous region to point to the new free region */

	if (prev) {
		assert(prev->magic == SHMAP_ALLOC_MAGIC);

		prev->next_free = shmap_alloc_to_shared(alloc, add);

		if ((rc = region_mutex_unlock(prev)))
			shmap_err("Failed to release prev lock on %p: %d\n",
				  shmap_alloc_to_shared(alloc, prev), rc);
	}
}

struct shmap_alloc *
shmap_alloc_init_ops(const struct shmap_alloc_pool_ops *ops, void *ctx,
		      void *base, size_t len, uint32_t flags)
{
	struct shmap_alloc_region *empty, *first, *end;
	struct shmap_alloc *alloc;
	size_t pool_off;
	size_t need;
	int rc;

	shmap_trace("Initialising allocator as %s\n",
		     (flags & SHMAP_FLAG_OWN) ? "owner" : "borrower");

	if (!(ops && ctx && base)) {
		shmap_trace("Bad configuration: %p, %p, %p\n", ops, ctx, base);
		return NULL;
	}

	if (!(ops->xlate_private &&
			ops->xlate_shared &&
			ops->contains &&
			ops->grow)) {
		shmap_trace("Missing callback(s)\n");
		return NULL;
	}

	shmap_trace("Populating local configuration with base @ %p for %zu \n",
		     base, len);

	alloc = malloc(sizeof(*alloc));
	if (!alloc)
		return NULL;

	/* Initialise local data */
	alloc->pool = base;
	alloc->ops = *ops;
	alloc->ctx = ctx;

	/* Skip pool preparation if we don't own it */
	if (!(flags & SHMAP_FLAG_OWN))
		return alloc;

	/* Set struct shmap_alloc_pool's null sentinel */
	memset(alloc->pool, 0, sizeof(*alloc->pool));

	/* Enforce a minimum size with the fun of self-hosting */
	pool_off = align_up(sizeof(*alloc->pool),
			    alignof(typeof(*alloc->pool->free)));
	need = pool_off + 2 * shmap_alloc_region_size(0);
	if (len < need) {
		/* We could, but why cause ourselves the pain? */
		shmap_err("Cannot init allocator with only %zuB available, need %zuB\n",
			  len, need);
		return NULL;
	}

	shmap_trace("Initialising pool metadata\n");

	/* Initialise free-list head */
	empty = (void __as_private *)(shmap_u_private(base) + pool_off);
	alloc->pool->free = shmap_alloc_to_shared(alloc, empty);

	end = (void __as_private *)(shmap_u_private(base) + len);
	(void)end;
	shmap_trace("Pool begins at %p and has size %zuB after %zuB metadata, ends at %p\n",
		    alloc->pool->free, len - pool_off, pool_off, end);

	if ((rc = shmap_alloc_region_init(alloc, empty, 0))) {
		shmap_err("Failed to initialise free sentinel: %d\n", rc);
		return NULL;
	}

	/* Initialise the first allocatable region */
	first = shmap_alloc_region_next(alloc, empty);

	assert(first);
	len = len - pool_off - (2 * shmap_alloc_region_size(0));
	if ((rc = shmap_alloc_region_init(alloc, first, len))) {
		shmap_err("Failed to initialise free region: %d\n", rc);
		return NULL;
	}
	shmap_alloc_add_free(alloc, first);

	shmap_trace("Allocator initialisation complete\n");

	return alloc;
}

void shmap_alloc_destroy(struct shmap_alloc *alloc)
{
	shmap_trace("Destroying allocator\n");

	free(alloc);
}

void shmap_alloc_set_user(struct shmap_alloc *alloc, void __as_shared *user)
{
	alloc->pool->user = user;
}

void __as_shared *shmap_alloc_get_user(struct shmap_alloc *alloc)
{
	return alloc->pool->user;
}


void __as_shared *shmap_alloc_malloc(struct shmap_alloc *alloc, size_t size)
{
	struct shmap_alloc_region *region, *remaining;
	int rc;

	if (!size)
		return NULL;

	shmap_trace("Requested allocation for free region of %zuB\n", size);

	do {
		region = shmap_alloc_take_free(alloc, size);
		if (region)
			break;

		rc = shmap_alloc_region_allocate(alloc, size, &region);
	/* Can get EAGAIN if the pool was remapped while acquiring a region */
	} while (!region && rc == -EAGAIN);

	if (!region && rc) {
		shmap_err("Failed to allocate new region: %d\n", rc);
		return NULL;
	}

	shmap_trace("Examining whether to split %p after %zuB\n",
		    shmap_alloc_to_shared(alloc, region), size);

	remaining = shmap_alloc_region_split(alloc, region, size);

	if (remaining) {
		shmap_trace("Inserting remainder at %p for %zuB into free list\n",
			    shmap_alloc_to_shared(alloc, remaining),
			    remaining->len);
		shmap_alloc_add_free(alloc, remaining);
	}

	return shmap_alloc_to_shared(alloc, region->data);
}

#if SHMAP_ALLOC_COALESCE
static void shmap_alloc_region_destroy(struct shmap_alloc *alloc,
				       struct shmap_alloc_region *region)
{
	int rc;

	/* Wait for all users to evacuate the region */
	if ((rc = region_mutex_lock(region))) {
		shmap_err("Failed to lock region %p for destruction\n",
			  shmap_alloc_to_shared(alloc, region));
		assert(false);
		return;
	}

	region->magic = ~SHMAP_ALLOC_MAGIC;

	if ((rc = region_mutex_unlock(region))) {
		shmap_err("Failed to unlock region %p\n",
			  shmap_alloc_to_shared(alloc, region));
		assert(false);
		return;
	}

	if ((rc = region_mutex_destroy(region)))
		shmap_err("Failed to destroy alloc lock on %p: %d\n",
			  shmap_alloc_to_shared(alloc, region), rc);
}

static int shmap_alloc_coalesce_free(struct shmap_alloc *alloc,
				      struct shmap_alloc_region *region)
{
	struct shmap_alloc_region *curr, *adjacent;
	int rc;

	assert(region->magic == SHMAP_ALLOC_MAGIC);

	adjacent = shmap_alloc_region_next(alloc, region);
	if (!adjacent)
		return 0;

	if (adjacent->magic != SHMAP_ALLOC_MAGIC) {
		shmap_trace("Region calculation gave %p but there's no magic there!\n",
			     shmap_alloc_to_shared(alloc, adjacent));
		return 0;
	}

	shmap_trace("Attempting to coalesce %p into adjacent region %p\n",
		    shmap_alloc_to_shared(alloc, region),
		    shmap_alloc_to_shared(alloc, adjacent));

	/* Coalesce opportunistically, if we can't get the lock then bail */
	if (region_mutex_trylock(adjacent))
		return 0;

	shmap_trace("Acquired adjacent lock with trylock, assessing free state\n");

	/* Can't coalesce allocated regions */
	if (adjacent->state == shmap_alloc_s_allocated) {
		if ((rc = region_mutex_unlock(adjacent))) {
			shmap_err("Failed to release adjacent lock on %p: %d\n",
				  shmap_alloc_to_shared(alloc, adjacent), rc);
			return rc;
		}

		return 0;
	}

	/*
	 * "Allocate" the adjacent region so we can coalesce. After allocation
	 * we can drop the lock to allow concurrent traversal over the region.
	 */
	adjacent->state = shmap_alloc_s_allocated;
	if ((rc = region_mutex_unlock(adjacent))) {
		shmap_err("Failed to release adjacent lock on %p: %d\n",
			  shmap_alloc_to_shared(alloc, adjacent), rc);
		return rc;
	}

	shmap_trace("Coalescing %p into adjacent region %p\n",
		    shmap_alloc_to_shared(alloc, region),
		    shmap_alloc_to_shared(alloc, adjacent));

	/* Find the free list entry pointing to the adjacent region */
	curr = shmap_alloc_to_private(alloc, alloc->pool->free);
	if ((rc = region_mutex_lock(curr))) {
		shmap_err("Failed to acquire curr lock on %p: %d\n",
			  shmap_alloc_to_shared(alloc, curr), rc);
		return rc;
	}

	while (curr->next_free != shmap_alloc_to_shared(alloc, adjacent) &&
			curr->next_free) {
		struct shmap_alloc_region __as_private *next_free;

		next_free = shmap_alloc_to_private(alloc, curr->next_free);

		if ((rc = region_mutex_lock(next_free))) {
			shmap_err("Failed to acquire next_free lock on %p: %d\n",
				  shmap_alloc_to_shared(alloc, next_free), rc);

			if ((rc = region_mutex_unlock(curr))) {
				shmap_err("Failed to release curr lock on %p: %d\n",
					  shmap_alloc_to_shared(alloc, curr),
					  rc);
			}

			return rc;
		}

		if ((rc = region_mutex_unlock(curr))) {
			shmap_err("Failed to release curr lock on %p: %d\n",
				  shmap_alloc_to_shared(alloc, curr), -rc);
			return rc;
		}
		curr = next_free;
	}

	shmap_trace("Free region %p had %p as next free region\n",
		    shmap_alloc_to_shared(alloc, curr),
		    shmap_alloc_to_shared(alloc, adjacent));

	/* Re-acquire adjacent's lock for consistency of ->next_free */
	if ((rc = region_mutex_lock(adjacent))) {
		shmap_err("Failed to re-acquire adjacent lock on %p: %d\n",
			  shmap_alloc_to_shared(alloc, adjacent), rc);
		goto cleanup_curr_lock;
	}

	if (curr->next_free) {
		/* Drop adjacent out of the free list */
		assert(curr->next_free == shmap_alloc_to_shared(alloc, adjacent));
		/* region is not in the free list, skip over adjacent */
		curr->next_free = adjacent->next_free;
		shmap_trace("%p is now next for %p\n", curr->next_free,
			    shmap_alloc_to_shared(alloc, curr));
	}

	if ((rc = region_mutex_unlock(adjacent))) {
		shmap_err("Failed to release adjacent lock on %p: %d\n",
			  shmap_alloc_to_shared(alloc, adjacent), rc);
		goto cleanup_curr_lock;
	}

	if ((rc = region_mutex_unlock(curr))) {
		shmap_err("Failed to release curr lock on %p: %d\n",
			  shmap_alloc_to_shared(alloc, curr), -rc);
		return rc;
	}

	/* Merge the adjacent region into the provided region */
	region->len = align_up(region->len, alignof(typeof(*region)));
	region->len += shmap_alloc_region_size(adjacent->len);

	shmap_trace("Merged adjacent region %p into %p (now %zuB), destroying adjacent\n",
		    shmap_alloc_to_shared(alloc, adjacent),
		    shmap_alloc_to_shared(alloc, region), region->len);

	shmap_alloc_region_destroy(alloc, adjacent);

	/* Try the subsequent adjacent region */
	return shmap_alloc_coalesce_free(alloc, region);

cleanup_curr_lock:
	if ((rc = region_mutex_unlock(curr)))
		shmap_err("Failed to release curr lock on %p: %d\n",
			  shmap_alloc_to_shared(alloc, curr), -rc);

	return rc;
}
#endif

void shmap_alloc_free(struct shmap_alloc *alloc, void __as_shared *ptr)
{
	struct shmap_alloc_region __as_private *region;
	int rc;

	if (!ptr)
		return;

	if (shmap_u_shared(ptr) & (alignof(typeof(*region)) - 1)) {
		shmap_err("Unaligned pointer provided to %s: %p\n",
			  __func__, ptr);
		return;
	}

	region = to_shmap_alloc_region(shmap_alloc_to_private(alloc, ptr));
	if (region->magic != SHMAP_ALLOC_MAGIC) {
		shmap_err("Bad pointer provided to %s: %p\n", __func__, ptr);
		return;
	}

	shmap_trace("Request to free region %p from data %p\n",
		    shmap_alloc_to_shared(alloc, region), ptr);

	assert(region->state == shmap_alloc_s_allocated);
	if (region->state != shmap_alloc_s_allocated) {
		shmap_err("Double free on %p\n",
			  shmap_alloc_to_shared(alloc, region));
		return;
	}

	if ((rc = region_mutex_lock(region))) {
		shmap_err("Failed to lock region %p: %d\n",
			  shmap_alloc_to_shared(alloc, region), rc);
		return;
	}

	assert(region->state == shmap_alloc_s_allocated);

#if SHMAP_ALLOC_COALESCE
	if ((rc = shmap_alloc_coalesce_free(alloc, region))) {
		shmap_err("Failed to coalesce region %p: %d\n",
			  shmap_alloc_to_shared(alloc, region), rc);
		goto unlock;
	}
#endif
	shmap_alloc_add_free(alloc, region);

unlock:
	if ((rc = region_mutex_unlock(region))) {
		shmap_err("Failed to unlock region %p: %d\n",
			  shmap_alloc_to_shared(alloc, region), rc);
		return;
	}
}

void __as_shared *shmap_alloc_realloc(struct shmap_alloc *alloc,
				      void __as_shared *ptr,
				      size_t len)
{
	struct shmap_alloc_region __as_private *region;
	void __as_shared *adj;

	if (!ptr)
		return NULL;

	if (shmap_u_shared(ptr) & (alignof(typeof(*region)) - 1)) {
		shmap_err("Unaligned pointer provided to %s: %p\n",
			  __func__, ptr);
		return NULL;
	}

	region = to_shmap_alloc_region(shmap_alloc_to_private(alloc, ptr));
	if (region->magic != SHMAP_ALLOC_MAGIC) {
		shmap_err("Bad pointer provided to %s: %p\n", __func__, ptr);
		return NULL;
	}

	if (len == region->len)
		return ptr;

	shmap_trace("Resizing region at %p from %zu to %zu bytes\n",
		    shmap_alloc_to_shared(alloc, region), region->len, len);

	/* TODO: Optimise to opportunistically expand provided region */
	if (len) {
		void __as_private *src, *dst;
		size_t copy;

		/* region becomes invalid after shmap_alloc_malloc, test here */
		copy = len < region->len ? len : region->len;

		adj = shmap_alloc_malloc(alloc, len);
		if (adj) {
			src = shmap_alloc_to_private(alloc, ptr);
			dst = shmap_alloc_to_private(alloc, adj);
			memcpy(dst, src, copy);
		}
	} else {
		adj = NULL;
	}

	shmap_alloc_free(alloc, ptr);

	return adj;
}
