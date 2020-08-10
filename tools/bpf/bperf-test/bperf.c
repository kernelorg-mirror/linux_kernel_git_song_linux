// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2019 Facebook
#define _GNU_SOURCE         /* See feature_test_macros(7) */
#include <unistd.h>
#include <sys/syscall.h>   /* For SYS_xxx definitions */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/ioctl.h>
#include <time.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <linux/perf_event.h>
#include <errno.h>
#include "bperf.h"
#include "bperf.skel.h"

#define EVENT_MAP_PATH "/sys/fs/bpf/event_map"
#define BSS_MAP_PATH "/sys/fs/bpf/bss"
#define PROG_PATH "/sys/fs/bpf/prog"
#define LINK_PATH "/sys/fs/bpf/link"

static int load_fd(void)
{
	struct perf_event_attr attr = {
		.type = PERF_TYPE_SOFTWARE,
		.size = sizeof(struct perf_event_attr),
	};
	struct bperf_bpf *skel;
	struct bpf_link *link;
	int pmu_fd, map_fd;
	__u32 key = 0;
	int ret = 1;

	skel = bperf_bpf__open_and_load();

	pmu_fd = syscall(__NR_perf_event_open, &attr, -1 /* pid */, 0 /* cpu */,
			 -1 /* group_fd */, 0);
	if (pmu_fd < 0) {
		fprintf(stderr, "failed to open pmu_fd\n");
		goto out;
	}

	map_fd = bpf_map__fd(skel->maps.events);

	if (map_fd < 0 ||
	    bpf_map_update_elem(map_fd, &key, &pmu_fd, BPF_ANY) ||
	    ioctl(pmu_fd, PERF_EVENT_IOC_ENABLE, 0)) {
		fprintf(stderr, "failed to enabled event and update the map\n");
		return 1;
	}

	link = bpf_program__attach(skel->progs.func);

	if (bpf_obj_pin(map_fd, EVENT_MAP_PATH))
		fprintf(stderr, "failed to pin the event map\n");

	if (bpf_obj_pin(bpf_map__fd(skel->maps.bss), BSS_MAP_PATH))
		fprintf(stderr, "failed to pin the bss map\n");

	if (bpf_obj_pin(bpf_program__fd(skel->progs.func), PROG_PATH))
		fprintf(stderr, "failed to pin the prog\n");

	ret = bpf_link__fd(link);
	fprintf(stderr, "link fd = %d\n", ret);
	if (bpf_obj_pin(ret, LINK_PATH))
		fprintf(stderr, "failed to pin the link: %d\n", errno);

	ret = 0;
	syscall(__NR_getpgid);
	syscall(__NR_getpgid);
	sleep(60);
out:
	return ret;
}

static int run_prog(void)
{
	int map_fd;

	map_fd = bpf_obj_get(EVENT_MAP_PATH);

	if (map_fd < 0) {
		fprintf(stderr, "failed to open map_fd\n");
		return 1;
	}

	syscall(__NR_getpgid);

	close(map_fd);
	return 0;
}

static void usage(int argc, char **argv)
{
	fprintf(stderr, "%s: [load|run]\n", argv[0]);
	exit(0);
}

int main(int argc, char **argv)
{
	if (argc != 2)
		usage(argc, argv);

	if (strcmp(argv[1], "load") == 0)
		return load_fd();
	if (strcmp(argv[1], "run") == 0)
		return run_prog();
	usage(argc, argv);
	return 0;
}
