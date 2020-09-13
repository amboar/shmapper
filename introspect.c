// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2020,2021 IBM Corp.

#define _GNU_SOURCE

#include "interface.h"
#include "introspect.h"

#include <errno.h>
#include <expat.h>
#include <stdio.h>
#include <stdlib.h>

enum introspect_parse_state {
	parse_state_init,
	parse_state_root,
	parse_state_interface,
	parse_state_node,
	parse_state_complete,
};

struct introspect_path {
	shmapper_connection_t connection;
	shmapper_path_t path;
};

struct introspect_path_node {
	struct introspect_path_node *next;

	struct introspect_path path;
};

struct introspect_descriptor {
	struct introspect_path *path;
	char *descriptor;
};

struct introspect_parse_data {
	const struct introspect_descriptor *descriptor;
	struct introspect_path_node **paths;
	enum introspect_parse_state state;
	struct shmapper *shmapper;
};

static int introspect_fetch(sd_bus *bus, struct introspect_path *path,
			    struct introspect_descriptor *descriptor)
{
        sd_bus_error error = SD_BUS_ERROR_NULL;
	sd_bus_message *reply = NULL;
	char *xml;
	int rc;

	rc = sd_bus_call_method(bus,
				path->connection.connection,
				path->path.path,
				"org.freedesktop.DBus.Introspectable",
				"Introspect",
				&error,
				&reply,
				"");
        if (rc < 0) {
                fprintf(stderr, "Failed to call method: %s\n", error.message);
                goto finish;
        }

	rc = sd_bus_message_read_basic(reply, 's', &xml);
	if (rc < 0) {
		fprintf(stderr, "Failed to parse response message: %s\n",
				strerror(-rc));
		goto finish;
	}

	descriptor->path = path;
	/* FIXME: Go zero-copy by keeping the message in scope */
	descriptor->descriptor = strdup(xml);

finish:
	fflush(stderr);
	sd_bus_error_free(&error);
	sd_bus_message_unref(reply);

	return rc < 0 ? rc : 0;
}

static const char *introspect_el_name(const char **attr)
{
	int i;

	for (i = 0; attr[i] && strcmp("name", attr[i]); i += 2);

	/* FIXME */
	assert(attr[i]);

	return attr[i + 1];
}

static void
introspect_add_interface(struct introspect_parse_data *pdata,
			 struct introspect_path *curr,
			 const char **attr)
{
	struct shmapper_path_map __as_shared *paths;
	struct shmapper *shmapper;
	shmapper_interface_t iface;
	int rc;

	iface = shmapper_interface(introspect_el_name(attr));
	shmapper = pdata->shmapper;
	paths = shmap_private(shmapper->shmap, shmapper->data)->paths;
	rc = shmapper_path_map_add_interface(pdata->shmapper->shmap,
					     paths,
					     curr->path,
					     curr->connection,
					     iface);
	assert(!rc);

	printf("%s\t%s\t%s\n", curr->path.path, curr->connection.connection,
	       iface.interface);

	(void)rc;
}

static void
introspect_queue_path(struct introspect_parse_data *pdata,
		      struct introspect_path *curr,
		      const char **attr)
{
	struct introspect_path_node *node;
	const char *relpath;
	char *abspath = NULL;
	int rc;

	/* Find the node name */
	relpath = introspect_el_name(attr);

	/* Create the new path */
	node = malloc(sizeof(*node));
	assert(node);

	node->next = *pdata->paths;
	/* FIXME: curr->connection may be for a different connection */
	node->path.connection = curr->connection;

	if (!strcmp("/", curr->path.path))
		rc = asprintf(&abspath, "/%s", relpath);
	else
		rc = asprintf(&abspath, "%s/%s", curr->path.path, relpath);
	assert(rc > 0);
	assert(abspath);

	node->path.path = shmapper_path(abspath);

	/* Insert the path into the fetch list */
	*pdata->paths = node;

	(void)rc;
}

static void XMLCALL
introspect_el_start(void *data, const char *el, const char **attr)
{
	struct introspect_parse_data *pdata = data;
	struct introspect_path *curr;

	curr = pdata->descriptor->path;

	switch (pdata->state) {
	case parse_state_init:
		if (!strcmp("node", el))
			pdata->state = parse_state_root;
		break;
	case parse_state_root:
		if (!strcmp("interface", el)) {
			pdata->state = parse_state_interface;
			introspect_add_interface(pdata, curr, attr);
		} else if (!strcmp("node", el)) {
			pdata->state = parse_state_node;
			introspect_queue_path(pdata, curr, attr);
		}
		break;
	case parse_state_interface:
	case parse_state_node:
		break;
	case parse_state_complete:
		assert(false);
		break;
	}
}

static void XMLCALL introspect_el_end(void *data, const char *el)
{
	struct introspect_parse_data *pdata = data;

	switch (pdata->state) {
	case parse_state_init:
	case parse_state_complete:
		assert(false);
		break;
	case parse_state_root:
		if (!strcmp("node", el))
			pdata->state = parse_state_complete;
		break;
	case parse_state_interface:
		if (!strcmp("interface", el))
			pdata->state = parse_state_root;
		break;
	case parse_state_node:
		if (!strcmp("node", el))
			pdata->state = parse_state_root;
		break;
	}
}

static int introspect_parse(const struct introspect_descriptor *desc,
			    struct introspect_path_node **paths,
			    struct shmapper *shmapper)
{
	struct introspect_parse_data pdata;
	XML_Parser p;
	int done;
	int len;

	p = XML_ParserCreate(NULL);
	if (!p) {
		fprintf(stderr, "Couldn't allocate memory for parser\n");
		exit(-1);
	}

	pdata.descriptor = desc;
	pdata.paths = paths;
	pdata.shmapper = shmapper;
	pdata.state = parse_state_init;

	XML_SetUserData(p, &pdata);

	XML_SetElementHandler(p, introspect_el_start, introspect_el_end);

	len = strlen(desc->descriptor);
	done = 1;
	if (XML_Parse(p, desc->descriptor, len, done) == XML_STATUS_ERROR) {
		fprintf(stderr,
			"Parse error at line %lu: %s\n",
			XML_GetCurrentLineNumber(p),
			XML_ErrorString(XML_GetErrorCode(p)));
		exit(-1);
	}

	XML_ParserFree(p);

	free(desc->descriptor);

	return 0;
}

int
introspect_connection(sd_bus *bus, shmapper_connection_t connection,
		      struct shmapper *shmapper)
{
	struct introspect_descriptor _desc, *desc = &_desc;
	struct introspect_path_node *head, *curr;
	int res;
	int rc;

	head = malloc(sizeof(*head));
	if (!head)
		return -ENOMEM;

	head->next = NULL;
	head->path.connection = connection;
	head->path.path = shmapper_path(strdup("/"));

	/* Fixed-point introspection: Iterate until there's nothing left */
	while (head) {
		curr = head;
		head = head->next;

		if ((rc = introspect_fetch(bus, &curr->path, desc)))
			goto cleanup_nodes;

		if ((rc = shmapper_wrlock(shmapper)))
			goto cleanup_nodes;

		rc = introspect_parse(desc, &head, shmapper);

		res = shmapper_unlock(shmapper);

		free((void *)curr->path.path.path);
		free(curr);

		if ((rc = rc ?: res))
			goto cleanup_nodes;
	}

	return 0;

cleanup_nodes:
	if (curr)
		free((void *)curr->path.path.path);
	free(curr);

	while (head) {
		struct introspect_path_node *curr;

		curr = head;
		head = head->next;

		free((void *)curr->path.path.path);
		free(curr);
	}

	return rc;
}

char **introspect_list_connections(sd_bus *bus)
{
        sd_bus_error error = SD_BUS_ERROR_NULL;
	sd_bus_message *reply = NULL;
	char **names = NULL;
	int rc;

	rc = sd_bus_call_method(bus,
				"org.freedesktop.DBus",
				"/org/freedesktop/DBus",
				"org.freedesktop.DBus",
				"ListNames",
				&error,
				&reply,
				"");
        if (rc < 0) {
                fprintf(stderr, "Failed to call method: %s\n", error.message);
                goto finish;
        }

        /* Parse the response message */
        rc = sd_bus_message_read_strv(reply, &names);
        if (rc < 0) {
                fprintf(stderr, "Failed to parse response message: %s\n",
			strerror(-rc));
        }

finish:
	sd_bus_error_free(&error);
	sd_bus_message_unref(reply);

	return names;
}
