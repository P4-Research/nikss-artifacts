# PSA-eBPF artifacts

## Topology

TBD

## Generator machine

Steps to follow to prepare the generator machine. 

### Install required software

### Configure TRex

## DUT machine

Steps to follow to prepare the DUT machine. 

### Hardware settings & OS configuration

TBD by Frederic

### Build p4c-ebpf-psa

### Build P4-DPDK

### Build OVS

## Steps to reproduce tests

We use `setup_test.sh` script to automatically deploy test configurations. Before running the script export the `P4C_REPO` variable, which is used by `setup_test.sh`
to find P4C repository.

```
$ export P4C_REPO=<path-to-p4c-ebpf-psa-root-directory>
``` 

The basic usage of `setup_test.sh` is as follows:

```
$ ./setup_test.sh --help
Run benchmark tests for PSA-eBPF.
The script will configure and deploy the PSA-eBPF setup for benchmarking.

Syntax: ./setup_test.sh [OPTIONS] [PROGRAM]

Example: ./setup_test.sh -p ens1f0,ens1f1 -c commands.txt testdata/l2fwd.p4

OPTIONS:
-p|--port-list     Comma separated list of interfaces that should be used for testing. (mandatory)
-c|--cmd           Path to the file containing runtime configuration for P4 tables/BPF maps.
-C|--core          CPU core that will be pinned to interfaces.
--help             Print this message.

PROGRAM:           P4 file (will be compiled by PSA-eBPF and then clang) or C file (will be compiled just by clang). (mandatory)

```

### 01. Sample test 1

### 02. Sample test 2
