// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2020,2021 IBM Corp.

#include "vec.h"
#include "trace.h"

#include <errno.h>
#include <string.h>

struct shmap_vec {
	void __as_shared * __as_shared *vec;
	size_t size;
	size_t capacity;
};

struct shmap_vec __as_shared *
shmap_vec_init(struct shmap *shmap, size_t capacity)
{
	void __as_shared *data;
	struct shmap_vec __as_shared *vec;

	if (capacity > (SIZE_MAX / sizeof(*vec->vec)))
		return NULL;

	if (!capacity)
		capacity = 16; /* Arbitrary power of two */

	shmap_trace("Initialising vec with capacity %zu\n", capacity);

	vec = shmap_malloc(shmap, sizeof(*vec));
	if (!vec)
		return NULL;

	data = shmap_malloc(shmap, sizeof(*vec->vec) * capacity);
	if (!data)
		goto cleanup_vec;
	shmap_private(shmap, vec)->vec = data;

	shmap_private(shmap, vec)->size = 0;
	shmap_private(shmap, vec)->capacity = capacity;

	return vec;

cleanup_vec:
	shmap_free(shmap, vec);

	return NULL;
}

void shmap_vec_destroy(struct shmap *shmap, struct shmap_vec __as_shared *vec)
{
	shmap_trace("Destroying vec\n");
	shmap_free(shmap, shmap_private(shmap, vec)->vec);
	shmap_free(shmap, vec);
}

bool shmap_vec_is_empty(struct shmap *shmap, struct shmap_vec __as_shared *vec)
{
	shmap_trace("%d\n", shmap_private(shmap, vec)->size == 0);

	return shmap_private(shmap, vec)->size == 0;
}

size_t shmap_vec_size(struct shmap *shmap, struct shmap_vec __as_shared *vec)
{
	shmap_trace("%zu\n", shmap_private(shmap, vec)->size);

	return shmap_private(shmap, vec)->size;
}

void __as_shared *shmap_vec_get(struct shmap *shmap,
				struct shmap_vec __as_shared *vec, size_t idx)
{
	void __as_shared *obj;

	if (shmap_private(shmap, vec)->size <= idx)
		return NULL;

	obj = shmap_private(shmap, shmap_private(shmap, vec)->vec)[idx];

	shmap_trace("Fetched entry %p at %zu\n", obj, idx);

	return obj;
}

int shmap_vec_insert(struct shmap *shmap, struct shmap_vec __as_shared *vec,
		     void __as_shared *obj, size_t idx)
{
	void __as_shared *top;

	if (idx > shmap_private(shmap, vec)->size)
		return -EINVAL;

	shmap_trace("Inserting entry %p at %zu\n", obj, idx);

	if (shmap_private(shmap, vec)->size ==
			shmap_private(shmap, vec)->capacity) {
		void __as_shared * __as_shared *adj;
		size_t new_capacity = 2 * shmap_private(shmap, vec)->capacity;

		shmap_trace("Expanding capacity to %zu\n", new_capacity);

		adj = shmap_realloc(shmap, shmap_private(shmap, vec)->vec,
				    new_capacity * sizeof(*vec->vec));
		if (!adj)
			return -ENOMEM;

		shmap_private(shmap, vec)->vec = adj;
		shmap_private(shmap, vec)->capacity = new_capacity;
	}

	top = shmap_vec_peek(shmap, vec);

	if (idx == shmap_private(shmap, vec)->size) {
		shmap_private(shmap, shmap_private(shmap, vec)->vec)[idx] = obj;
		goto done;
	}

	assert(shmap_private(shmap, vec)->size <
			shmap_private(shmap, vec)->capacity);
	assert(idx < shmap_private(shmap, vec)->size);

	memmove(&shmap_private(shmap, shmap_private(shmap, vec)->vec)[idx + 1],
		&shmap_private(shmap, shmap_private(shmap, vec)->vec)[idx],
		(shmap_private(shmap, vec)->size - idx) * sizeof(*vec->vec));
	shmap_private(shmap, shmap_private(shmap, vec)->vec)[idx] = obj;

done:
	shmap_private(shmap, vec)->size++;

	if (shmap_private(shmap, vec)->size > 1) {
		(void)top;
		assert(top == shmap_vec_peek(shmap, vec));
	}

	return 0;
}

int shmap_vec_remove(struct shmap *shmap, struct shmap_vec __as_shared *vec,
		     size_t idx)
{
	if (idx >= shmap_private(shmap, vec)->size)
		return -EINVAL;

	shmap_trace("Removing entry at %zu\n", idx);

	if (idx + 1 == shmap_private(shmap, vec)->size)
		goto done;

	memmove(&shmap_private(shmap, shmap_private(shmap, vec)->vec)[idx],
		&shmap_private(shmap, shmap_private(shmap, vec)->vec)[idx + 1],
		(shmap_private(shmap, vec)->size - 1 - idx) * sizeof(*vec->vec));

done:
	shmap_private(shmap, vec)->size--;

	return 0;
}

int shmap_vec_push(struct shmap *shmap, struct shmap_vec __as_shared *vec,
		   void __as_shared *obj)
{
	shmap_trace("Pushing entry %p\n", obj);

	return shmap_vec_insert(shmap, vec, obj,
				shmap_private(shmap, vec)->size);
}

void __as_shared *
shmap_vec_pop(struct shmap *shmap, struct shmap_vec __as_shared *vec)
{
	void __as_shared *entry;
	size_t idx;
	int rc;

	if (!shmap_private(shmap, vec)->size)
		return NULL;

	shmap_trace("Popping entry\n");

	idx = shmap_private(shmap, vec)->size - 1;

	entry = shmap_vec_get(shmap, vec, idx);

	if ((rc = shmap_vec_remove(shmap, vec, idx)))
		return NULL;

	return entry;
}

void __as_shared *
shmap_vec_peek(struct shmap *shmap, struct shmap_vec __as_shared *vec)
{
	shmap_trace("Peeking entry\n");

	return shmap_vec_get(shmap, vec, shmap_private(shmap, vec)->size - 1);
}
