// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2019 Facebook
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

#ifndef PERF_MAX_STACK_DEPTH
#define PERF_MAX_STACK_DEPTH         127
#endif

#ifndef BPF_F_USER_STACK
#define BPF_F_USER_STACK		(1ULL << 8)
#endif

typedef __u64 stack_trace_t[PERF_MAX_STACK_DEPTH];

struct {
	__uint(type, BPF_MAP_TYPE_STACK_TRACE);
	__uint(max_entries, 16384);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(stack_trace_t));
} stackmap SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16384);
	__type(key, __u32);
	__type(value, __u32);
} stackid_hmap SEC(".maps");

#define CALLCHAIN_SIZE_MAX__ 64
struct perf_callchain_entry_ {
	__u64		nr;
	__u64		ip[CALLCHAIN_SIZE_MAX__]; /* /proc/sys/kernel/perf_event_max_stack */
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct perf_callchain_entry_);

} callchain_map SEC(".maps");

SEC("perf_event")
int oncpu(struct bpf_perf_event_data *ctx)
{
	__u32 max_len = PERF_MAX_STACK_DEPTH * sizeof(__u64);
	struct perf_callchain_entry_ *callchain;
	struct bpf_perf_event_data_kern ctx_;
	struct perf_sample_data data;
	__u32 key = 0, val = 0, *value_p;
	void *stack_p;
	int i, count;

	bpf_probe_read_kernel(&ctx_, sizeof(ctx_), ctx);
	bpf_probe_read_kernel(&data, sizeof(data), ctx_.data);
	if (data.callchain) {
		callchain = bpf_map_lookup_elem(&callchain_map, &key);
		if (callchain) {
			bpf_probe_read_kernel(callchain,
					      sizeof(struct perf_callchain_entry_),
					      data.callchain);
			bpf_printk("callchain.nr %lld\n", callchain->nr);
			for (i = 0; i < CALLCHAIN_SIZE_MAX__; i++) {
				if (i < callchain->nr)
					bpf_printk("callchain.ip[%d] = %llx\n", i,
						   callchain->ip[i]);
			}
		}
	}

	return 0;
}


char LICENSE[] SEC("license") = "GPL";
