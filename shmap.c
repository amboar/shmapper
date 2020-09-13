// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2020,2021 IBM Corp.

#include "alloc.h"
#include "pool.h"
#include "shmap.h"
#include "trace.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <semaphore.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

struct shmap {
	char path[NAME_MAX];

	sem_t *sem;

	int (*user_destroy)(struct shmap *shmap, void __as_shared *user);

	struct shmap_pool pool;
};

struct shmap *shmap_init(const char *name, uint32_t flags, size_t user_len,
			 int (*user_init)(struct shmap *shmap,
					  void __as_shared *user),
			 int (*user_destroy)(struct shmap *shmap,
				 	     void __as_shared *user))
{
	struct shmap *shmap;
	bool owned;
	int rc;

	owned = flags & SHMAP_FLAG_OWN;
	if (!owned && (user_len || user_init)) {
		shmap_err("Borrower cannot initialise user region\n");
		return NULL;
	}

	shmap_trace("Initialising shmap\n");

	if (!(shmap = malloc(sizeof(*shmap))))
		return NULL;

	shmap_trace("Deriving shared resource path\n");
	rc = snprintf(shmap->path, sizeof(shmap->path), "/%s", name);
	if (rc < 0) {
		shmap_err("Failed to form resource path: %d\n", -errno);
		goto cleanup_shmap;
	}

	if ((size_t)rc >= sizeof(shmap->path)) {
		shmap_err("snprintf failed: %d\n", -ENOSPC);
		goto cleanup_shmap;
	}

	shmap_trace("Initialising sem\n");

	/* Create the global lock */
	shmap->sem = sem_open(shmap->path, O_RDWR | O_CREAT, 0666, 0);
	if (shmap->sem == SEM_FAILED) {
		shmap_err("Failed to open sem: %d\n", -errno);
		goto cleanup_shmap;
	}

	shmap_trace("Created sem from %s at %p\n", shmap->path, shmap->sem);

	/* If borrowed, wait for the owner to complete init */
	if (!owned) {
		if (sem_wait(shmap->sem)) {
			shmap_err("Failed to acquire sem: %d\n", -errno);
			goto cleanup_sem;
		}
	}

	shmap_trace("Initialising shm pool\n");

	if ((rc = shmap_pool_init(&shmap->pool, shmap->path, flags)))
		goto cleanup_shmap;

	shmap_trace("Initialised shmap\n");

	if (!owned)
		goto release_sem;

	/* Initialise user data */
	if (user_len) {
		if ((rc = shmap_pool_read_lock(&shmap->pool))) {
			shmap_err("Failed to acquire pool read lock: %d\n", rc);
			goto cleanup_sem;
		}

		/* No helper for setting user data as it's only done here */
		shmap_alloc_set_user(shmap->pool.alloc,
				     shmap_alloc_malloc(shmap->pool.alloc,
							user_len));

		if ((rc = shmap_pool_read_unlock(&shmap->pool))) {
			shmap_err("Failed to release pool read lock: %d\n", rc);
			goto cleanup_user;
		}

		if (!shmap_get_user(shmap)) {
			shmap_err("Failed to allocate user data\n");
			goto cleanup_sem;
		}
	}

	if (user_init) {
		/* user_init() must reacquire the pool read lock if they care */
		if ((rc = user_init(shmap, shmap_get_user(shmap)))) {
			shmap_err("User init failed: %d\n", rc);
			goto cleanup_user;
		}
	}

	shmap->user_destroy = user_destroy;

release_sem:
	/* If borrowed, return the resource. If owner, release borrowers */
	if (sem_post(shmap->sem)) {
		shmap_err("Failed to release sem: %d\n", -errno);
	}

	return shmap;

cleanup_user:
	shmap_alloc_free(shmap->pool.alloc, shmap_get_user(shmap));

cleanup_sem:
	if (owned)
		if (sem_unlink(shmap->path))
			shmap_err("Failed to unlink sem %s: %d\n",
				  shmap->path, -errno);

	if (sem_close(shmap->sem))
		shmap_err("Failed to close sem: %d\n", -errno);

cleanup_shmap:
	free(shmap);
	return NULL;
}

void shmap_destroy(struct shmap *shmap)
{
	int rc;

	if (!shmap)
		return;

	if (sem_wait(shmap->sem)) {
		shmap_err("Failed to acquire sem: %d\n", -errno);
		return;
	}

	/* FIXME: abstraction violation */
	if (shmap->pool.base->refs == 1) {
		shmap_trace("Removing sem\n");
		if (sem_unlink(shmap->path))
			shmap_err("Failed to unlink sem: %d\n" -errno);

		if (shmap->user_destroy && (rc = shmap->user_destroy(shmap,
						       shmap_get_user(shmap))))
			shmap_err("Failed to destroy user allocation\n");
	}

	shmap_trace("Releasing shm\n");

	/* Destroy sem if shm is gone */
	if ((rc = shmap_pool_destroy(&shmap->pool)) < 0)
		shmap_err("Failed to destroy pool: %d\n", rc);

	shmap_trace("Releasing sem\n");
	if (sem_post(shmap->sem))
		shmap_trace("Failed to release sem: %d\n", -errno);

	if (sem_close(shmap->sem))
		shmap_err("Failed to close sem: %d\n", -errno);

	shmap_trace("Cleaning up shmap\n");
	free(shmap);
}

int shmap_lock(struct shmap *shmap)
{
	return shmap_pool_read_lock(&shmap->pool);
}

int shmap_unlock(struct shmap *shmap)
{
	return shmap_pool_read_unlock(&shmap->pool);
}

void __as_shared *shmap_get_user(const struct shmap *shmap)
{
	return shmap_alloc_get_user(shmap->pool.alloc);
}

void __as_shared *shmap_malloc(struct shmap *shmap, size_t size)
{
	return shmap_alloc_malloc(shmap->pool.alloc, size);
}

void shmap_free(struct shmap *shmap, void __as_shared *ptr)
{
	return shmap_alloc_free(shmap->pool.alloc, ptr);
}

void __as_shared *shmap_realloc(struct shmap *shmap, void __as_shared *ptr,
				size_t sz)
{
	return shmap_alloc_realloc(shmap->pool.alloc, ptr, sz);
}

char __as_shared *shmap_strdup(struct shmap *shmap, const char *str)
{
	char __as_shared *dupped;

	dupped = shmap_malloc(shmap, strlen(str) + 1);
	if (!dupped)
		return NULL;

	strcpy(shmap_private(shmap, dupped), str);

	return dupped;
}

static pthread_mutex_t __as_private *
to_pthread_mutex(struct shmap *shmap, struct shmap_mutex __as_shared *mutex)
{
	return &shmap_private(shmap, mutex)->mutex;
}

int shmap_mutex_init(struct shmap *shmap, struct shmap_mutex __as_shared *mutex)
{
	pthread_mutexattr_t attr;
	int res;
	int rc;

	shmap_trace("Setting up mutex at %p\n", mutex);

	if ((rc = -pthread_mutexattr_init(&attr)))
		return rc;

	if ((rc = -pthread_mutexattr_setpshared(&attr, PTHREAD_PROCESS_SHARED)))
		return rc;

	res = -pthread_mutex_init(to_pthread_mutex(shmap, mutex), &attr);

	if ((rc = -pthread_mutexattr_destroy(&attr)))
		return rc;

	return res;
}

int shmap_mutex_lock(struct shmap *shmap, struct shmap_mutex __as_shared *mutex)
{
	pthread_mutex_t __as_private *pt_mutex;
	int rc, res;

	shmap_trace("Acquiring mutex at %p\n", mutex);

	pt_mutex = to_pthread_mutex(shmap, mutex);
	
	if ((rc = shmap_unlock(shmap)))
		return rc;

	res = -pthread_mutex_lock(pt_mutex);

	if ((rc = shmap_lock(shmap)))
		return rc;

	return res;
}

int shmap_mutex_unlock(struct shmap *shmap,
		       struct shmap_mutex __as_shared *mutex)
{
	shmap_trace("Releasing mutex at %p\n", mutex);
	return -pthread_mutex_unlock(to_pthread_mutex(shmap, mutex));
}

int shmap_mutex_destroy(struct shmap *shmap,
			struct shmap_mutex __as_shared *mutex)
{
	shmap_trace("Destroying mutex at %p\n", mutex);
	return -pthread_mutex_destroy(to_pthread_mutex(shmap, mutex));
}

static pthread_cond_t __as_private *
to_pthread_cond(struct shmap *shmap, struct shmap_cond __as_shared *cond)
{
	return &shmap_private(shmap, cond)->cond;
}

int shmap_cond_init(struct shmap *shmap, struct shmap_cond __as_shared *cond)
{
	pthread_condattr_t attr;
	int res;
	int rc;

	shmap_trace("Initialising cond at %p\n", cond);

	if ((rc = pthread_condattr_init(&attr)))
		return rc;

	if ((rc = pthread_condattr_setpshared(&attr, PTHREAD_PROCESS_SHARED)))
		return rc;

	res = -pthread_cond_init(to_pthread_cond(shmap, cond), &attr);

	if ((rc = pthread_condattr_destroy(&attr)))
		return rc;

	return res;
}

int shmap_cond_signal(struct shmap *shmap, struct shmap_cond __as_shared *cond)
{
	shmap_trace("Signalling cond at %p\n", cond);
	return -pthread_cond_signal(to_pthread_cond(shmap, cond));
}

int shmap_cond_broadcast(struct shmap *shmap,
			 struct shmap_cond __as_shared *cond)
{
	shmap_trace("Broadcast-signalling cond at %p\n", cond);
	return -pthread_cond_broadcast(to_pthread_cond(shmap, cond));
}

int shmap_cond_wait(struct shmap *shmap, struct shmap_cond __as_shared *cond,
		    struct shmap_mutex __as_shared *mutex)
{
	pthread_mutex_t __as_private *pt_mutex;
	pthread_cond_t __as_private *pt_cond;
	int res;
	int rc;

	shmap_trace("Awaiting signal on cond %p under mutex %p\n", cond, mutex);

	pt_cond = to_pthread_cond(shmap, cond);
	pt_mutex = to_pthread_mutex(shmap, mutex);

	if ((rc = shmap_unlock(shmap)))
		return rc;

	res = -pthread_cond_wait(pt_cond, pt_mutex);

	if ((rc = shmap_lock(shmap)))
		return rc;

	return res;
}

int shmap_cond_destroy(struct shmap *shmap, struct shmap_cond __as_shared *cond)
{
	shmap_trace("Destroying cond at %p\n", cond);
	return -pthread_cond_destroy(to_pthread_cond(shmap, cond));
}

const void __as_private *__shmap_private(struct shmap *shmap,
					 const void __as_shared *pointer)
{
	return shmap_alloc_to_private(shmap->pool.alloc, pointer);
}

const void __as_shared *__shmap_shared(struct shmap *shmap,
				       const void __as_private *pointer)
{
	return shmap_alloc_to_shared(shmap->pool.alloc, pointer);
}

static pthread_rwlock_t __as_private *
to_pthread_rwlock(struct shmap *shmap, struct shmap_rwlock __as_shared *rwlock)
{
	return &shmap_private(shmap, rwlock)->rwlock;
}

int shmap_rwlock_init(struct shmap *shmap,
		      struct shmap_rwlock __as_shared *rwlock)
{
	pthread_rwlockattr_t attr;
	int res;
	int rc;

	shmap_trace("Setting up rwlock at %p\n", rwlock);

	if ((rc = -pthread_rwlockattr_init(&attr)))
		return rc;

	if ((rc = -pthread_rwlockattr_setpshared(&attr,
						 PTHREAD_PROCESS_SHARED)))
		return rc;

	res = -pthread_rwlock_init(to_pthread_rwlock(shmap, rwlock), &attr);

	if ((rc = -pthread_rwlockattr_destroy(&attr)))
		return rc;

	return res;
}

int shmap_rwlock_rdlock(struct shmap *shmap,
			struct shmap_rwlock __as_shared *rwlock)
{
	pthread_rwlock_t __as_private *pt_rwlock;
	int rc, res;

	shmap_trace("Acquiring read-lock at %p\n", rwlock);

	pt_rwlock = to_pthread_rwlock(shmap, rwlock);
	
	if ((rc = shmap_unlock(shmap)))
		return rc;

	res = -pthread_rwlock_rdlock(pt_rwlock);

	if ((rc = shmap_lock(shmap)))
		return rc;

	return res;
}

int shmap_rwlock_wrlock(struct shmap *shmap,
			struct shmap_rwlock __as_shared *rwlock)
{
	pthread_rwlock_t __as_private *pt_rwlock;
	int rc, res;

	shmap_trace("Acquiring write-lock at %p\n", rwlock);

	pt_rwlock = to_pthread_rwlock(shmap, rwlock);
	
	if ((rc = shmap_unlock(shmap)))
		return rc;

	res = -pthread_rwlock_wrlock(pt_rwlock);

	if ((rc = shmap_lock(shmap)))
		return rc;

	return res;
}

int shmap_rwlock_unlock(struct shmap *shmap,
			struct shmap_rwlock __as_shared *rwlock)
{
	return pthread_rwlock_unlock(to_pthread_rwlock(shmap, rwlock));
}

int shmap_rwlock_destroy(struct shmap *shmap,
			 struct shmap_rwlock __as_shared *rwlock)
{
	return -pthread_rwlock_destroy(to_pthread_rwlock(shmap, rwlock));
}
