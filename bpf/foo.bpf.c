/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2021 Hengqi Chen */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

// comment out to make it "work"
#define BREAK

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__uint(key_size, sizeof(u64));
	__uint(value_size, sizeof(u32));
} mount_ns_set SEC(".maps");

SEC("kprobe/vfs_read")
int BPF_KPROBE(vfs_read_entry, struct file *file, char *buf, size_t count, loff_t *pos)
{
	struct task_struct *task;
	u64 mntns_id = 0;

#ifdef BREAK
	task = (struct task_struct*)bpf_get_current_task();
	mntns_id = (u64) BPF_CORE_READ(task, nsproxy, mnt_ns, ns.inum);
#endif

	if (!bpf_map_lookup_elem(&mount_ns_set, &mntns_id))
		return 0;

	return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
