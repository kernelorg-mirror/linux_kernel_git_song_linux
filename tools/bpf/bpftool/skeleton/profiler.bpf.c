// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2020 Facebook
#include "profiler.h"
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#define ___bpf_concat(a, b) a ## b
#define ___bpf_apply(fn, n) ___bpf_concat(fn, n)
#define ___bpf_nth(_, _1, _2, _3, _4, _5, _6, _7, _8, _9, _a, _b, _c, N, ...) N
#define ___bpf_narg(...) \
	___bpf_nth(_, ##__VA_ARGS__, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0)
#define ___bpf_empty(...) \
	___bpf_nth(_, ##__VA_ARGS__, N, N, N, N, N, N, N, N, N, N, 0)

#define ___bpf_ctx_cast0() ctx
#define ___bpf_ctx_cast1(x) ___bpf_ctx_cast0(), (void *)ctx[0]
#define ___bpf_ctx_cast2(x, args...) ___bpf_ctx_cast1(args), (void *)ctx[1]
#define ___bpf_ctx_cast3(x, args...) ___bpf_ctx_cast2(args), (void *)ctx[2]
#define ___bpf_ctx_cast4(x, args...) ___bpf_ctx_cast3(args), (void *)ctx[3]
#define ___bpf_ctx_cast5(x, args...) ___bpf_ctx_cast4(args), (void *)ctx[4]
#define ___bpf_ctx_cast6(x, args...) ___bpf_ctx_cast5(args), (void *)ctx[5]
#define ___bpf_ctx_cast7(x, args...) ___bpf_ctx_cast6(args), (void *)ctx[6]
#define ___bpf_ctx_cast8(x, args...) ___bpf_ctx_cast7(args), (void *)ctx[7]
#define ___bpf_ctx_cast9(x, args...) ___bpf_ctx_cast8(args), (void *)ctx[8]
#define ___bpf_ctx_cast10(x, args...) ___bpf_ctx_cast9(args), (void *)ctx[9]
#define ___bpf_ctx_cast11(x, args...) ___bpf_ctx_cast10(args), (void *)ctx[10]
#define ___bpf_ctx_cast12(x, args...) ___bpf_ctx_cast11(args), (void *)ctx[11]
#define ___bpf_ctx_cast(args...) \
	___bpf_apply(___bpf_ctx_cast, ___bpf_narg(args))(args)

/*
 * BPF_PROG is a convenience wrapper for generic tp_btf/fentry/fexit and
 * similar kinds of BPF programs, that accept input arguments as a single
 * pointer to untyped u64 array, where each u64 can actually be a typed
 * pointer or integer of different size. Instead of requring user to write
 * manual casts and work with array elements by index, BPF_PROG macro
 * allows user to declare a list of named and typed input arguments in the
 * same syntax as for normal C function. All the casting is hidden and
 * performed transparently, while user code can just assume working with
 * function arguments of specified type and name.
 *
 * Original raw context argument is preserved as well as 'ctx' argument.
 * This is useful when using BPF helpers that expect original context
 * as one of the parameters (e.g., for bpf_perf_event_output()).
 */
#define BPF_PROG(name, args...)						    \
name(unsigned long long *ctx);						    \
static __always_inline typeof(name(0))					    \
____##name(unsigned long long *ctx, ##args);				    \
typeof(name(0)) name(unsigned long long *ctx)				    \
{									    \
	_Pragma("GCC diagnostic push")					    \
	_Pragma("GCC diagnostic ignored \"-Wint-conversion\"")		    \
	return ____##name(___bpf_ctx_cast(args));			    \
	_Pragma("GCC diagnostic pop")					    \
}									    \
static __always_inline typeof(name(0))					    \
____##name(unsigned long long *ctx, ##args)

/* map of perf event fds, num_cpu * num_metric entries */
struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(int));
} events SEC(".maps");

/* readings at fentry */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(struct bpf_perf_event_value));
} fentry_readings SEC(".maps");

/* accumulated readings */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(struct bpf_perf_event_value));
} accum_readings SEC(".maps");

/* sample counts, one per cpu */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u64));
} counts SEC(".maps");

const volatile __u32 num_cpu = 1;
const volatile __u32 num_metric = 1;
#define MAX_NUM_MATRICS 4

SEC("fentry/XXX")
int BPF_PROG(fentry_XXX)
{
	struct bpf_perf_event_value *ptrs[MAX_NUM_MATRICS];
	u32 key = bpf_get_smp_processor_id();
	u32 i;

	/* look up before reading, to reduce error */
	for (i = 0; i < num_metric && i < MAX_NUM_MATRICS; i++) {
		u32 flag = i;

		ptrs[i] = bpf_map_lookup_elem(&fentry_readings, &flag);
		if (!ptrs[i])
			return 0;
	}

	for (i = 0; i < num_metric && i < MAX_NUM_MATRICS; i++) {
		struct bpf_perf_event_value reading;
		int err;

		err = bpf_perf_event_read_value(&events, key, &reading,
						sizeof(reading));
		if (err)
			return 0;
		*(ptrs[i]) = reading;
		key += num_cpu;
	}

	return 0;
}

static inline void
fexit_update_maps(u32 id, struct bpf_perf_event_value *after)
{
	struct bpf_perf_event_value *before, diff, *accum;

	before = bpf_map_lookup_elem(&fentry_readings, &id);
	/* only account samples with a valid fentry_reading */
	if (before && before->counter) {
		struct bpf_perf_event_value *accum;

		diff.counter = after->counter - before->counter;
		diff.enabled = after->enabled - before->enabled;
		diff.running = after->running - before->running;

		accum = bpf_map_lookup_elem(&accum_readings, &id);
		if (accum) {
			accum->counter += diff.counter;
			accum->enabled += diff.enabled;
			accum->running += diff.running;
		}
	}
}

SEC("fexit/XXX")
int BPF_PROG(fexit_XXX)
{
	struct bpf_perf_event_value readings[MAX_NUM_MATRICS];
	u32 cpu = bpf_get_smp_processor_id();
	u32 i, one = 1, zero = 0;
	int err;
	u64 *count;

	/* read all events before updating the maps, to reduce error */
	for (i = 0; i < num_metric && i < MAX_NUM_MATRICS; i++) {
		err = bpf_perf_event_read_value(&events, cpu + i * num_cpu,
						readings + i, sizeof(*readings));
		if (err)
			return 0;
	}
	count = bpf_map_lookup_elem(&counts, &zero);
	if (count) {
		*count += 1;
		for (i = 0; i < num_metric && i < MAX_NUM_MATRICS; i++)
			fexit_update_maps(i, &readings[i]);
	}
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
