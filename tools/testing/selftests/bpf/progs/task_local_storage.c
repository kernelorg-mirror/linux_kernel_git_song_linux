// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2020 Facebook */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

struct local_data {
	int val;
};

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct local_data);
} task_storage_map SEC(".maps");

__u32 test_progs_pid;
int value;

SEC("tp_btf/sched_switch")
int BPF_PROG(on_switch, bool preempt, struct task_struct *prev,
	     struct task_struct *next)
{
	__u32 pid = bpf_get_current_pid_tgid() >> 32;
	struct local_data *storage;

	if (pid != test_progs_pid)
		return 0;
	storage = bpf_task_storage_get(&task_storage_map,
				       bpf_get_current_task_btf(), 0,
				       BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (storage) {
		storage->val++;
		value = storage->val;
	}
	return 0;
}
