/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2020,2021 IBM Corp. */

#ifndef SHMAP_H
#define SHMAP_H

#include "address.h"

#include <pthread.h>
#include <stddef.h>
#include <stdint.h>

struct shmap;

#define SHMAP_FLAG_OWN		(1UL << 0)
struct shmap *shmap_init(const char *name, uint32_t flags, size_t user_len,
			 int (*user_init)(struct shmap *shmap,
					  void __as_shared *user),
			 int (*user_destroy)(struct shmap *shmap,
					    void __as_shared *user));
void shmap_destroy(struct shmap *shmap);

int shmap_lock(struct shmap *shmap);
int shmap_unlock(struct shmap *shmap);

/* Convert a shared pointer to a private pointer for dereferencing */
#define shmap_private(shmap, pointer) \
	((typeof(*pointer) __as_private *)  __shmap_private(shmap, pointer))

/* Convert a private pointer to a shared pointer for storage */
#define shmap_shared(shmap, pointer) \
	((typeof(*pointer) __as_shared *) __shmap_shared(shmap, pointer))

/* Create a shared pointer to a member of a struct through a shared pointer */
#define shmap_ref(shmap, container, member) \
({ \
 	typeof(shmap) __shmap = shmap; \
 	shmap_shared(__shmap, &shmap_private(__shmap, container)->member); \
})

void __as_shared *shmap_get_user(const struct shmap *shmap);

void __as_shared *shmap_malloc(struct shmap *shmap, size_t size);
void shmap_free(struct shmap *shmap, void __as_shared *ptr);
void __as_shared *shmap_realloc(struct shmap *shmap, void __as_shared *ptr,
				size_t sz);

char __as_shared *shmap_strdup(struct shmap *shmap, const char *str);

struct shmap_mutex {
	pthread_mutex_t mutex;
};

int shmap_mutex_init(struct shmap *shmap,
		     struct shmap_mutex __as_shared *mutex);
int shmap_mutex_lock(struct shmap *shmap,
		     struct shmap_mutex __as_shared *mutex);
int shmap_mutex_unlock(struct shmap *shmap,
		       struct shmap_mutex __as_shared *mutex);
int shmap_mutex_destroy(struct shmap *shmap,
			struct shmap_mutex __as_shared *mutex);

struct shmap_cond {
	pthread_cond_t cond;
};

int shmap_cond_init(struct shmap *shmap, struct shmap_cond __as_shared *cond);
int shmap_cond_signal(struct shmap *shmap, struct shmap_cond __as_shared *cond);
int shmap_cond_broadcast(struct shmap *shmap,
			 struct shmap_cond __as_shared *cond);
int shmap_cond_wait(struct shmap *shmap, struct shmap_cond __as_shared *cond,
		    struct shmap_mutex __as_shared *mutex);
int shmap_cond_destroy(struct shmap *shmap,
		struct shmap_cond __as_shared *cond);

struct shmap_rwlock {
	pthread_rwlock_t rwlock;
};

int shmap_rwlock_init(struct shmap *shmap,
		      struct shmap_rwlock __as_shared *rwlock);
int shmap_rwlock_rdlock(struct shmap *shmap,
			struct shmap_rwlock __as_shared *rwlock);
int shmap_rwlock_wrlock(struct shmap *shmap,
			struct shmap_rwlock __as_shared *rwlock);
int shmap_rwlock_unlock(struct shmap *shmap,
			struct shmap_rwlock __as_shared *rwlock);
int shmap_rwlock_destroy(struct shmap *shmap,
			 struct shmap_rwlock __as_shared *rwlock);

/* Helpers, use the convenience wrappers instead */
const void __as_private *__shmap_private(struct shmap *shmap,
					 const void __as_shared *pointer);
const void __as_shared *__shmap_shared(struct shmap *shmap,
				       const void __as_private *pointer);
#endif
