/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2020,2021 IBM Corp. */

#ifndef SHMAPPER_INTROSPECT_H
#define SHMAPPER_INTROSPECT_H

#include "connection.h"
#include "shmapper.h"

#include <systemd/sd-bus.h>

char **introspect_list_connections(sd_bus *bus);

int introspect_connection(sd_bus *bus, shmapper_connection_t connection,
			  struct shmapper *shmapper);
#endif
