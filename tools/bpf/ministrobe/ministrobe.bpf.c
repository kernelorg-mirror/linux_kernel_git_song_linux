// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2019 Facebook
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#ifndef PERF_MAX_STACK_DEPTH
#define PERF_MAX_STACK_DEPTH         127
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

SEC("perf_event")
int oncpu(void *ctx)
{
	__u32 max_len = PERF_MAX_STACK_DEPTH * sizeof(__u64);
	__u32 key = 0, val = 0, *value_p;
	void *stack_p;

	/* The size of stackmap and stackid_hmap should be the same */
	key = bpf_get_stackid(ctx, &stackmap, 0);
	if ((int)key >= 0)
		bpf_map_update_elem(&stackid_hmap, &key, &val, 0);

	key = bpf_get_stackid(ctx, &stackmap, BPF_F_USER_STACK);
	if ((int)key >= 0)
		bpf_map_update_elem(&stackid_hmap, &key, &val, 0);

	return 0;
}


char LICENSE[] SEC("license") = "GPL";
