// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2020,2021 IBM Corp.

#include "../hash.h"

#include <assert.h>
#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(void)
{
	struct shmap_hash _hash, *hash = &_hash;
	uint8_t data[UINT8_MAX];
	uint32_t res;
	uint8_t len;
	ssize_t got;

	got = read(0, &len, sizeof(len));
	if (got < 0) {
		perror("read");
		exit(EXIT_FAILURE);
	}

	assert(got == sizeof(len));

	if (!len)
		exit(EXIT_SUCCESS);

	got = read(0, data, len);
	if (got < 0) {
		perror("read");
		exit(EXIT_FAILURE);
	}

	shmap_hash_init(hash);

	shmap_hash_update(hash, data, len);

	res = shmap_hash_value(hash);

	printf("0x%08" PRIx32 "\n", res);

	return 0;
}
