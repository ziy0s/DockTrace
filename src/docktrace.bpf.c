#include "../include/vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
// #include <bpf/libbpf.h>

char LICENSE[] SEC("license") = "GPL";

struct event {
  u32 pid;
  __u64 cgroup_id;
  char container_id[65];
  char comm[16];
  char command[128];
};

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, __u32);
} host_inode SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1 << 20); // 1048576 (1M)

} rb SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_execve")
int execve_entry(struct syscall_trace_enter *ctx) {

  __u32 key = 0;

  __u32 *host_inum;

  u64 cgroup_id = bpf_get_current_cgroup_id();
  struct event *e;

  struct task_struct *task = (struct task_struct *)bpf_get_current_task();

  host_inum = bpf_map_lookup_elem(&host_inode, &key);

  if (!host_inum)
    return 0;

  unsigned int namespace_inum = BPF_CORE_READ(task, nsproxy, ipc_ns, ns.inum);
  if (*host_inum == namespace_inum)
    return 0;

  e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
  if (!e)
    return 1;
  e->pid = bpf_get_current_pid_tgid() >> 32;
  bpf_get_current_comm(&e->comm, sizeof(e->comm));
  e->cgroup_id = cgroup_id;

  const char *filename = (const char *)ctx->args[0];
  bpf_probe_read_user_str(&e->command, sizeof(e->command), filename);

  bpf_ringbuf_submit(e, 0);

  return 0;
}