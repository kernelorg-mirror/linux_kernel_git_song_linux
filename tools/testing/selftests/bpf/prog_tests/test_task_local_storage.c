// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2020 Facebook */

#include <sys/types.h>
#include <unistd.h>
#include <test_progs.h>
#include "task_local_storage.skel.h"

static unsigned int duration;

void test_test_task_local_storage(void)
{
	struct task_local_storage *skel;
	int i, err;

	skel = task_local_storage__open_and_load();

	if (CHECK(!skel, "skel_open_and_load", "skeleton open and load failed\n"))
		return;
	skel->bss->test_progs_pid = getpid();

	err = task_local_storage__attach(skel);

	if (CHECK(err, "skel_attach", "skeleton attach failed\n"))
		goto out;

	for (i = 0; i < 10; i++)
		usleep(10);
	CHECK(skel->bss->value < 10, "task_local_storage_value",
	      "task local value too small\n");

out:
	task_local_storage__destroy(skel);
}
