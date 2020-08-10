// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2019 Facebook
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "bperf.h"

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
	__uint(max_entries, 1);
} events SEC(".maps");

__u64 value = 0;

SEC("fentry/__x64_sys_getpgid")
int func(void *ctx)
{
	struct bpf_perf_event_value val;
	u32 key = 0;
	long err;

	bpf_printk("enter", value);
	err = bpf_perf_event_read_value(&events, key, &val, sizeof(val));
	if (err) {
		bpf_printk("err = %ld", err);
		return 0;
	}
	value = val.counter;
	bpf_printk("value = %llu", value);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
