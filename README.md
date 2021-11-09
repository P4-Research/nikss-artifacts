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

In order to make tests as stable and reproducible as possible and to minimize interference from system activity, the following configuration was done. Note that the same configuration is used for both PSA-eBPF in-kernel tests and P4-dpdk userspace tests. All our tests we done with DUT kernel version v5.11.3.
-  Disable HyperThreading
-  Disable Turbo Boost, either from UEFI/BIOS or as follows (assuming `intel_pstate` is enabled):
```
echo 1 > /sys/devices/system/cpu/intel_pstate/no_turbo
```
-  Set the CPU governor to *performance mode* so that all CPU cores run at the highest frequency possible:
```
for i in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor
do
	echo performance > $i
done
```
-  Stop the irqbalance service so that irq affinities can be set:
```
killall irqbalance
```
-  Use `isolcpu`, `rcu_ncbs` and `nohz_full` kernel boot-command-line parameters to isolate CPU cores that will be assigned to BPF or DPDK programs from system activity and kernel noise. For example, with a server with 32 physical CPU cores, the following configuration will leave only CPU core 0 for system activity and all other CPU cores for test programs:
```
isolcpus=1-31 rcu_nocbs=1-31 nohz_full=1-31
```
-  Allocate huge pages at boot time and disable transparent huge pages with the following  kernel boot parameters (e.g. 32 1GB huge pages):
```
default_hugepagesz=1G hugepagesz=1G hugepages=32 transparent_hugepage=never
```
- When assigning CPU cores to BPF or DPDK programs, avoid cross-NUMA traffic by selecting CPU cores that belong to the NUMA node where the NIC is located. For example, the NUMA node of NIC port `ens3f0` can be retrieved as follows:
```
cat /sys/class/net/ens3f0/device/numa_node
```

### Build p4c-ebpf-psa

### Build P4-DPDK

### Build OVS

Install OVS from source.

Clone Git repository:

```
$ git clone https://github.com/openvswitch/ovs.git
$ cd ovs
$ git checkout v2.16.0
```

Bootstrapping:

```
$ ./boot.sh
$ ./configure
$ make
$ make install
```

## Steps to reproduce tests

We use `setup_test.sh` script to automatically deploy test configurations. 

Before running the script you should prepare the environment file based on the template provided under `env/` directory.
Then, export all variables by using (remember to pass your env file):

```
$ set -a && source env/pllab.env
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

### 07. Multi-queue scaling

Assuming that isolated CPU cores on the NIC's NUMA node are within the range of 6-11,18-23, tune `--queues N` parameter to set a desired number of RX/TX queues per NIC. 

```
$ sudo -E ./setup_test.sh -q 2 -C 6-10 -p ,ens4f1 -c runtime_cmd/01_use_cases/l2l3_acl_routing.txt p4testdata/01_use_cases/l2l3_acl.p4
``` 
