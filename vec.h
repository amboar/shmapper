/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2020,2021 IBM Corp. */

#ifndef SHMAP_VEC_H
#define SHMAP_VEC_H

#include "address.h"
#include "shmap.h"

#include <stdbool.h>
#include <stddef.h>

struct shmap_vec;

/* Wildly unsafe, but ¯\_(ツ)_/¯ */

struct shmap_vec __as_shared *
shmap_vec_init(struct shmap *shmap, size_t capacity);
void shmap_vec_destroy(struct shmap *shmap, struct shmap_vec __as_shared *vec);

bool shmap_vec_is_empty(struct shmap *shmap, struct shmap_vec __as_shared *vec);
size_t shmap_vec_size(struct shmap *shmap, struct shmap_vec __as_shared *vec);
void __as_shared *shmap_vec_get(struct shmap *shmap,
				struct shmap_vec __as_shared *vec, size_t idx);
int shmap_vec_insert(struct shmap *shmap, struct shmap_vec __as_shared *vec,
		     void __as_shared *obj, size_t idx);
int shmap_vec_remove(struct shmap *shmap, struct shmap_vec __as_shared *vec,
		     size_t idx);
int shmap_vec_push(struct shmap *shmap, struct shmap_vec __as_shared *vec,
		   void __as_shared *obj);
void __as_shared *shmap_vec_pop(struct shmap *shamp,
				struct shmap_vec __as_shared *vec);
void __as_shared *shmap_vec_peek(struct shmap *shmap,
				 struct shmap_vec __as_shared *vec);

#endif
