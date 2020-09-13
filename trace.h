/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2020,2021 IBM Corp. */

#ifndef SHMAP_TRACE_H
#define SHMAP_TRACE_H

#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

#define shmap_err(fmt, ...) \
({ \
	static pid_t cpid = 0; \
	if (!cpid) \
		cpid = getpid(); \
	fflush(stderr); \
	fprintf(stdout, "[%u] %s:%d: " fmt, cpid, __func__, __LINE__, \
		##__VA_ARGS__); \
})

#ifdef NTRACE
#define shmap_trace(fmt, ...) ({ })
#else
#define shmap_trace(fmt, ...) \
({ \
 	static pid_t cpid = 0; \
	if (!cpid) \
		cpid = getpid(); \
	fprintf(stderr, "[%u] %s:%d: " fmt, cpid, __func__, __LINE__, \
		##__VA_ARGS__); \
})
#endif
#endif
