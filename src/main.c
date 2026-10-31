#include <asm-generic/errno-base.h>
#include <bpf/libbpf.h>
#include "docktrace.skel.h"
// #include "vmlinux.h"


struct event {
    int pid;
    char comm[16];
    char command[16];
};


static int handle_event(void *ctx, void *data, size_t data_sz)
{
    const struct event *e = data;
    printf("Received Event -> PID: %d, Comm: %s, Command: %s\n", e->pid, e->comm, e->command);
    return 0;
}


int main(void) {

    struct docktrace_bpf *skel;

    struct ring_buffer *rb = NULL;

    skel = docktrace_bpf__open_and_load();

    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return 1;
    }

    if (docktrace_bpf__attach(skel)) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        goto cleanup;
    }

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