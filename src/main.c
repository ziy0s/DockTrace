#define _GNU_SOURCE
#include "../include/docktrace.skel.h"
#include <asm-generic/errno-base.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <fcntl.h>
#include <linux/limits.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#ifndef FILEID_KERNFS
#define FILEID_KERNFS 0xfe
#endif

struct event {
  int pid;
  __u64 cgroup_id;
  char container_id[65];
  char comm[16];
  char command[128];
};

static int open_cgroup_by_id(__u64 id) {

    //  we use staruct here to fix out of the bounds compailer warning !
    //  with memcpy
  struct {
    struct file_handle fh;
    unsigned char data[sizeof(__u64)];
  } handler = {0};

  int mount_fd = open("/sys/fs/cgroup", O_RDONLY | O_DIRECTORY);
  if (mount_fd < 0)
    return -1;

  handler.fh.handle_bytes = sizeof(handler.data);
  handler.fh.handle_type = FILEID_KERNFS;

  memcpy(handler.fh.f_handle, &id, sizeof(id));

  int fd = open_by_handle_at(mount_fd, &handler.fh, O_RDONLY | O_DIRECTORY);
  close(mount_fd);

  return fd;
}

static int get_cgroup_path(__u64 inode_id, char *path, size_t size) {
  int fd = open_cgroup_by_id(inode_id);
  if (fd < 0)
    return -1;

  char proc_path[64];

  snprintf(proc_path, sizeof(proc_path), "/proc/self/fd/%d", fd);

  ssize_t len = readlink(proc_path, path, size - 1);

  close(fd);
  if (len < 0)
    return -1;

  path[len] = '\0';
  return 0;
}

static int get_container_id_by_path(char *path, char *container) {

    ssize_t path_len = strlen(path);
    ssize_t i = path_len - 1;

    char tmp[256];

    while (path[i]) {
        if (path[i] == '.')
            break ;
        if (path[i] == '-' || path[i] == '/')
            break ;
        i--;
    }
    // now i is point to . [.scope] or / [/cac82ec68dc6]

    if (path[i] == '.') {
        //  for Docker with Cgroup, Podman, Kubernetes => ../..-[container_id].scope
        int j = 0;
        while (path[i] != '-' && path[i] != '/')
            i--;
        i++;
        // now i is point to the head of the hash cac82ec68dc6

        while (path[i] != '.') {
            tmp[j] = path[i];
            i++;
            j++;
        }
        tmp[j] = '\0';
    } else if (path[i] == '/') {
        // for Docker with cgroupfs and containerd => .../[conatiner_id]
        i++;
        int j = 0;
        while (path[i]) {
            tmp[j] = path[i];
            i++;
            j++;
        }
        tmp[j] = '\0';

    }

    memcpy(container, tmp, 256);
    
    return 0;
}

static int handle_event(void *ctx, void *data, size_t data_sz) {
    const struct event *e = data;
    char path[PATH_MAX];
    char container_id[265];

    // extract cgroup file path from cgroup inode handler '/sys/fs/cgroup/system.slice/docker-cac82ec68dc644476d190f91f7bcf2514ce0e38ac56f76c878e4fda593d0ab15.scope'
    if (get_cgroup_path(e->cgroup_id, path, sizeof(path)) < 0)
        return 0;

    // extract container id from cgroup file path [cac82ec68dc644476d190f91f7bcf2514ce0e38ac56f76c878e4fda593d0ab15]
    if (get_container_id_by_path(path, container_id) < 0)
        return 0;

    printf("Container:\t%s\n", container_id);
    printf("PID:\t\t%d\n", e->pid);
    printf("Cgroup:\t\t%lld\n", e->cgroup_id);
    printf("Catalyzer:\t%s\n", e->comm);
    printf("Command:\t%s\n", e->command);
    printf("=====================================================\n");

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

  if (geteuid() != 0) {
      fprintf(stderr, "Error: This program requires root privileges to run.\n");
      fprintf(stderr, "Please re-run using 'sudo' or as the root user.\n");
      return -1;
  }

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
  printf("==================[Received Events]==================\n");


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
