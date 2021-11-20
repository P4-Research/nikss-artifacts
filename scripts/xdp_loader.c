#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

#include <net/if.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#define XDP_FLAGS_DRV_MODE		(1U << 2)

struct bpf_devmap_val {
	__u32 ifindex;   /* device index */
	union {
		int   fd;  /* prog fd on map write */
		__u32 id;  /* prog id on map read */
	} bpf_prog;
};

int main(int argc, char **argv)
{
    struct bpf_devmap_val devmap_val;
    int eg_prog_fd = -1;
    int devmap_fd = -1;

    int ifindex = if_nametoindex(argv[1]);
    if (!ifindex)
        return EINVAL;

    char pinned_file[256];

    snprintf(pinned_file, sizeof(pinned_file), "/sys/fs/bpf/prog/xdp_xdp-ingress");
    int ig_prog_fd = bpf_obj_get(pinned_file);
    if (ig_prog_fd < 0) {
        return -1;
    }

    __u32 flags = XDP_FLAGS_DRV_MODE;
    int ret = bpf_set_link_xdp_fd(ifindex, ig_prog_fd, flags);
    if (ret) {
        return ret;
    }

    memset(pinned_file, 0, sizeof(pinned_file));
    snprintf(pinned_file, sizeof(pinned_file), "/sys/fs/bpf/prog/xdp_devmap_xdp-egress");
    eg_prog_fd = bpf_obj_get(pinned_file);
    if (eg_prog_fd < 0)
        return 0;

    memset(pinned_file, 0, sizeof(pinned_file));
    snprintf(pinned_file, sizeof(pinned_file), "/sys/fs/bpf/tx_port");
    devmap_fd = bpf_obj_get(pinned_file);
    if (devmap_fd < 0) {
        return -1;
    }

    devmap_val.ifindex = ifindex;
    devmap_val.bpf_prog.fd = eg_prog_fd;
    ret = bpf_map_update_elem(devmap_fd, &ifindex, &devmap_val, 0);
    if (ret) {
        return ret;
    }
    return 0;
}
