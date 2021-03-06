/*
 * Test client that sends a test pattern and verifies what comes back from
 * the service.
 *
 *   Copyright (C) 2020 Olaf Kirch <okir@suse.de>
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>
#include <assert.h>
#include "shell.h"
#include "endpoint.h"
#include "testing.h"

static void
test_client_timing_update(struct test_client_timing *t)
{
	unsigned long ts = io_timestamp_ms();
	unsigned long delay;

	if (t->last_ts != 0 && ts > t->last_ts) {
		delay = ts - t->last_ts;
		if (delay > t->max_delay)
			t->max_delay = delay;
	}

	t->last_ts = ts;
}

static void
test_client_get_data(struct endpoint *ep, struct queue *q, struct sender *s)
{
	struct test_client_appdata *appdata = s->handle;
	size_t send_sz;

	send_sz = queue_tailroom(q);
	if (appdata->random_send)
		send_sz = test_random_size(send_sz);

	if (send_sz) {
		test_client_queue_pattern(q, &appdata->send_pos, send_sz);
		appdata->nsends++;

		if (test_progress)
			progress_indicate('.');
	}

	test_client_timing_update(&appdata->send_timing);
}

struct sender *
test_client_sender(void *handle)
{
	struct sender *s;

	s = calloc(1, sizeof(*s));
	s->handle = handle;
	s->get_data = test_client_get_data;

	return s;
}

static bool
test_client_push_data(struct endpoint *ep, struct queue *q, struct receiver *r)
{
	struct test_client_appdata *appdata = r->handle;
	size_t recv_sz;

	assert(q);
	assert(q == r->recvq);

	recv_sz = queue_available(q);
	test_trace("%s: %lu bytes of data available\n", __func__, (unsigned long) recv_sz);

	if (appdata->random_recv)
		recv_sz = test_random_size(recv_sz);
	test_client_recv_pattern(q, &appdata->recv_pos, recv_sz);
	appdata->nrecvs++;

	if (test_progress)
		progress_indicate('+');

	test_client_timing_update(&appdata->recv_timing);
	return false;
}

static void
test_client_close_callback(struct endpoint *ep, void *handle)
{
	struct test_client_appdata *appdata = handle;

	if (test_progress)
		progress_indicate('\n');

	test_trace("%s: socket about to be destroyed\n", __func__);
	appdata->closed = true;
}

struct receiver *
test_client_receiver(void *handle)
{
	struct receiver *r;

	r = calloc(1, sizeof(*r));
	r->handle = handle;
	r->push_data = test_client_push_data;
	r->recvq = &r->__queue;

	return r;
}

void
test_client_print_stats(const struct test_client_appdata *appdata)
{
	if (appdata->recv_timing.max_delay > 500) {
		fprintf(stderr, "FAIL: receive stalled for %lu ms\n", appdata->recv_timing.max_delay);
		exit(99);
	}
	if (appdata->send_timing.max_delay > 500) {
		fprintf(stderr, "FAIL: send stalled for %lu ms\n", appdata->send_timing.max_delay);
		exit(99);
	}

	printf("OK: sent %s bytes in %u chunks; received %s bytes in %u chunks. %lu bytes still in flight.\n",
			print_byte_count(appdata->send_pos), appdata->nsends,
			print_byte_count(appdata->recv_pos), appdata->nrecvs,
			appdata->send_pos - appdata->recv_pos);
}

void
test_client_appdata_init(struct test_client_appdata *appdata, bool random_send, bool random_recv)
{
	memset(appdata, 0, sizeof(*appdata));
	appdata->random_send = random_send;
	appdata->random_recv = random_recv;
	queue_init(&appdata->recvq);
}

struct endpoint *
test_client_create(int fd, const char *name, struct test_client_appdata *appdata)
{
	struct endpoint *ep;

	ep = endpoint_new_socket(fd);
	if (test_tracing)
		endpoint_set_debug(ep, name, -1);

	endpoint_set_upper_layer(ep,
			test_client_sender(appdata),
			test_client_receiver(appdata));

	endpoint_register_close_callback(ep, test_client_close_callback, appdata);

	io_register_endpoint(ep);
	return ep;
}
