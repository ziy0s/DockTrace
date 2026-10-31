#include "docktrace.skel.h"
// #include "vmlinux.h"
#include <asm-generic/errno-base.h>
#include <bpf/libbpf.h>
#include <stdio.h>
#include <sys/stat.h>
#include <bpf/bpf.h>
// #include "vmlinux.h"

struct event {
  int pid;
  __u64 cgroup_id;
  char container_id[65];
  char comm[16];
  char command[128];
};

static int handle_event(void *ctx, void *data, size_t data_sz) {
  const struct event *e = data;
  printf("Received Event -> PID: %d, Cgroup: %lld, Comm: %s, Command: %s\n", e->pid, e->cgroup_id, e->comm,
         e->command);

  return 0;
}

unsigned int get_host_namespace_inode() {
  struct stat s;

  if (!stat("/proc/1/ns/ipc", &s)) {
    return (unsigned int)s.st_ino;
  }
  return 0;
}

int main(void) {

  struct docktrace_bpf *skel;

  struct ring_buffer *rb = NULL;

  unsigned int host_inode = get_host_namespace_inode();

  if (host_inode == 0) {
    fprintf(stderr, "Failed to get host namespace inode\n");
    return -1;
  }

  skel = docktrace_bpf__open_and_load();

  if (!skel) {
    fprintf(stderr, "Failed to open and load BPF skeleton\n");
    return 1;
  }
  __u32 key = 0;

  int err = bpf_map_update_elem(bpf_map__fd(skel->maps.host_inode), &key,
                                &host_inode, BPF_ANY);

  if (err) {
    fprintf(stderr, "Failed to update config map\n");
    goto cleanup;
  }

  if (docktrace_bpf__attach(skel)) {
    fprintf(stderr, "Failed to attach BPF skeleton\n");
    goto cleanup;
  }

  //   int map_fd = bpf_object__find_map_fd_by_name(skel, "host_inode");


  rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
  if (!rb) {
    fprintf(stderr, "Failed to create ring buffer manager\n");
    goto cleanup;
  }

  printf("Successfully started! Polling for events... (Ctrl+C to exit)\n");

  while (1) {
    int err = ring_buffer__poll(rb, 100);
    if (err < 0 && err == -EPERM) {
      fprintf(stderr, "Error polling ring buffer: %d\n", err);
      break;
    }
  }

cleanup:
  ring_buffer__free(rb);
  docktrace_bpf__destroy(skel);
  return 0;

  return 0;
}