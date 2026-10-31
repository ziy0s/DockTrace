#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";


struct event {
    u32 pid;
    char comm[16];
    char command[16];
};


struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20); // 1048576 (1M)

} rb SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_execve")
int execve_entry(struct syscall_trace_enter *ctx) {

    // unsigned int host_inum;

    // bpf_map_lookup_elem

    unsigned int host_inum = 4026531841;
    struct event *e;

    struct task_struct *task = (struct task_struct *) bpf_get_current_task();

    unsigned int namespace_inum = BPF_CORE_READ(task, nsproxy, mnt_ns, ns.inum);

    if (host_inum != namespace_inum) {
            e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
            if (!e)
                return 1;
            e->pid = bpf_get_current_pid_tgid() >> 32;
            bpf_get_current_comm(&e->comm, sizeof(e->comm));

            const char *filename = (const char *)ctx->args[0]; 
            bpf_probe_read_user_str(&e->command, sizeof(e->command), filename);

            bpf_ringbuf_submit(e, 0);
    }
    
    return 0;
}