// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2019 Facebook
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <linux/perf_event.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "ministrobe.skel.h"

static void bump_memlock_rlimit(void)
{
	struct rlimit rlim_new = {
		.rlim_cur	= RLIM_INFINITY,
		.rlim_max	= RLIM_INFINITY,
	};

	if (setrlimit(RLIMIT_MEMLOCK, &rlim_new)) {
		fprintf(stderr, "Failed to bump memlock limit.\n");
		exit(1);
	}
}


int main(int argc, char **argv)
{
	struct ministrobe_bpf *skel;
	int *perf_fds = NULL;
	struct bpf_link **links = NULL;
	int num_cpu, i;

	bump_memlock_rlimit();

	skel = ministrobe_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open and load skeleton\n");
		return 1;
	}

	num_cpu = libbpf_num_possible_cpus();
	if (num_cpu <= 0) {
		fprintf(stderr, "failed to identify number of CPUs");
		goto out;
	}

	num_cpu = 1;

	perf_fds = calloc(sizeof(int), num_cpu);
	links = calloc(sizeof(struct bpf_link*), num_cpu);
	if (!perf_fds || !links) {
		fprintf(stderr, "failed to allocate memory for perf_fds or links");
		goto out;
	}

	for (i = 0; i < num_cpu; i++) {
		struct bpf_link *link;
		int pmu_fd;
		struct perf_event_attr attr = {
			/* .type = PERF_TYPE_SOFTWARE, */
			.type = PERF_TYPE_HARDWARE,
			.config = PERF_COUNT_HW_INSTRUCTIONS,
			.precise_ip = 2,
			.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_BRANCH_STACK |
				PERF_SAMPLE_CALLCHAIN,
			.branch_sample_type = PERF_SAMPLE_BRANCH_USER |
				PERF_SAMPLE_BRANCH_NO_FLAGS |
				PERF_SAMPLE_BRANCH_NO_CYCLES |
				PERF_SAMPLE_BRANCH_CALL_STACK,
			.sample_period = 500000,
			.size = sizeof(struct perf_event_attr),
		};

		pmu_fd = syscall(__NR_perf_event_open, &attr,
				 -1/*pid*/, i, -1/*group_fd*/, 0);
		if (pmu_fd < 0) {
			fprintf(stderr, "failed to open perf event on cpu %d for %s\n", i,
				strerror(errno));
			goto out;
		}

		link = bpf_program__attach_perf_event(skel->progs.oncpu, pmu_fd);
		links[i] = link;
	}

	usleep(1000000);
	for (i = 0; i < num_cpu; i++)
		bpf_link__destroy(links[i]);

	return 0;
out:
	if (perf_fds)
		free(perf_fds);

	ministrobe_bpf__destroy(skel);
	return 1;

}
