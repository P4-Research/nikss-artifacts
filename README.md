# PSA-eBPF artifacts

## Topology

TBD

## Generator machine

Steps to follow to prepare the generator machine. 

### Install required software

### Configure TRex

### Run netperf

Before using netperf, make sure that all interfaces are managed by Linux driver back:

```
$ cd trex/v2.92/
$ sudo ./dpdk_setup_ports.py -L
```

In order to make Netperf traffic traverse the DUT machine, we have to set up the Linux namespaces, so that packets will leave
local host. Use the following script to automatically setup Linux namespaces:

```
$ sudo ./scripts/setup_netperf.sh
```

Then, to run Netperf test:

```
sudo ip netns exec netperf-client netperf -H 10.0.0.2 -p 5555 -t TCP_RR -- -o min_latency,max_latency,mean_latency,transaction_rate,p50_latency,p90_latency,p99_latency
```

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

### Build PSA-eBPF

Follow the steps from the [psa-ebpf-psa](https://github.com/P4-Research/p4c-ebpf-psa) repository to install PSA-eBPF on DUT machine. 

### Build P4-DPDK

### Build BMv2

### Build OVS

```
$ git clone https://github.com/openvswitch/ovs.git
$ cd ovs
$ git checkout v2.16.0
$ ./boot.sh
$ ./configure
$ make
$ make install
```

In the case of any problems, please refer to the [official Open vSwitch installation guide](https://docs.openvswitch.org/en/latest/intro/install/index.html). 

## Steps to reproduce tests

We use `setup_test.sh` script to automatically deploy test configurations. 

Before running the script you should prepare the environment file based on the template provided under `env/` directory.

The basic usage of `setup_test.sh` is as follows:

```
$ ./setup_test.sh --help
Run benchmark tests for PSA-eBPF.
The script will configure and deploy the PSA-eBPF setup for benchmarking.

Syntax: ./setup_test.sh [OPTIONS] [PROGRAM]

Example: ./setup_test.sh -E env_file -c commands.txt testdata/l2fwd.p4

OPTIONS:
-E|--env          File with environment variables for DUT.
-c|--cmd           Path to the file containing runtime configuration for P4 tables/BPF maps.
-q|--queues        Set number of RX/TX queues per NIC (default 1).
-C|--core          CPU core that will be pinned to interfaces.
--p4args           P4ARGS for PSA-eBPF.
--help             Print this message.

PROGRAM:           P4 file (will be compiled by PSA-eBPF and then clang) or C file (will be compiled just by clang). (mandatory)
```

### 01. Packet forwarding rate

Run PSA-eBPF with L2L3-ACL program and switching rules on DUT machine: 

```
sudo -E ./setup_test.sh -C 6 -E <ENV-FILE> -c runtime_cmd/01_use_cases/l2l3_acl_switching.txt p4testdata/01_use_cases/l2l3_acl.p4
```

On Generator machine run the NDR script and tune `size=` parameter accordingly (use 64, 128, 256, 512, 1024, 1518 packet sizes).

```
./ndr --stl --port 0 1 --pdr <PDR> --pdr-error <PDR-ERROR> -o hu --force-map --profile stl/bench.py --prof-tun size=64  --verbose
```

### 02. End-to-end performance

#### DUT

```
$ sudo -E ./setup_test.sh -C 6 -E <ENV-FILE> -c <SCRIPT> <P4-PROGRAM>
```

Replacements:
- for UPF uplink (decap) testing replace `<SCRIPT>` with `runtime_cmd/01_use_cases/upf_ul.txt` and `<P4-PROGRAM` with `p4testdata/01_use_cases/upf.p4`
- for UPF downlink (encap) testing replace `<SCRIPT>` with `runtime_cmd/01_use_cases/upf_dl.txt` and `<P4-PROGRAM` with `p4testdata/01_use_cases/upf.p4`

#### Generator

`$ ./ndr --stl --port 0 1 --max-iterations 20 -t 60  --pdr <PDR> --pdr-error <PDR-ERROR> -o hu --force-map --profile <PROFILE>`

`<PROFILE>` values:
- for UPF: 
  - uplink: `--profile trex_scripts/upf_ul.py --prof-tun packet_len=64`
  - downlink: `--profile stl/bench.py --prof-tun size=64`
- for L2L3-ACL: 
- for BNG:
- for L2FWD: `--profile stl/bench.py --prof-tun size=64`

### 03. Microbenchmarking: the cost of PSA externs

#### DUT

```
$ sudo -E ./setup_test.sh -C 6 -E <ENV-FILE> -c <SCRIPT> <P4-PROGRAM>
```

Run the script for each P4 program located under `p4testadata/03_psa_externs/`. Replace `<P4-PROGRAM>` with the path to a given P4 program (e.g. `p4testdata/03_psa_externs/action-selector.p4` to test the ActionSelector extern). 

Replace `<SCRIPT>` with:
- `runtime_cmd/03_psa_externs/base_forwarding.txt` for baseline.p4, checksum.p4, counter.p4, digest.p4, direct-counter.p4, hash.p4, internet-checksum.p4, register-read.p4, register-write.p4
- `runtime_cmd/03_psa_externs/action_profile.txt` for action-profile.p4
- `runtime_cmd/03_psa_externs/meter.txt` for meter.p4
- `runtime_cmd/03_psa_externs/direct-meter.txt` for direct-meter.p4
- `runtime_cmd/03_psa_externs/action_selector.txt` for action-selector.p4

#### Generator

On the Generator machine the below command to test each P4 program:

```
./ndr --stl --port 0 1 --max-iterations 20 --iter-time 60 --pdr <PDR> --pdr-error <PDR-ERROR> -o hu --force-map --profile stl/bench.py --prof-tun size=64  --verbose
```

### 04. Microbenchmarking: P4 Table lookup time

### 05. Comparison with other host-based P4 platforms

### 06. Comparison with other software switches

#### Run PSA-eBPF

```
$ sudo -E ./setup_test.sh -C 6 --p4args "--hdr2Map --max-ternary-masks 3 --xdp --pipeline-opt --table-caching" -E <ENV-FILE> -c <RUNTIME_CMD> <P4-PROGRAM>
```

To test L2FWD program:
- replace `<RUNTIME_CMD>` with `runtime_cmd/00_warmup/l2fwd.txt`
- replace `<P4-PROGRAM>` with `p4testdata/00_warmup/l2fwd.p4`

To test VXLAN program (encap):
- replace `<RUNTIME_CMD>` with `runtime_cmd/06_software_switching/vxlan_vtep_encap.txt`
- replace `<P4-PROGRAM>` with `p4testdata/06_software_switching/vxlan_vtep.p4`

To test L2L3-ACL program:
- replace `<RUNTIME_CMD>` with `runtime_cmd/06_software_switching/l2l3_acl_simple.txt`
- replace `<P4-PROGRAM>` with `p4testdata/06_software_switching/l2l3_acl_simple.p4`

#### Run OVS

```
$ sudo -E ./setup_test.sh -C 6 -E <ENV-FILE> -c <SCRIPT> openvswitch
```

Replace `<SCRIPT>` with:
- `runtime_cmd/06_software_switching/ovs_l2fwd_start.sh` for L2FWD test case
- `runtime_cmd/06_software_switching/ovs_l2l3_acl_start.sh` for L2L3-ACL test case
- `runtime_cmd/06_software_switching/ovs_vxlan_encap_start.sh` for VXLAN (encap) test case

#### Run eBPF/XDP

```
$ sudo -E ./setup_test.sh -C 6 -E <ENV-FILE> -c <RUNTIME_CMD> <EBPF_PROG>
```

To test eBPF/XDP L2FWD program:
- replace `<RUNTIME_CMD>` with `runtime_cmd/06_software_switching/ebpf_l2fwd.txt`
- replace `<EBPF_PROG>` with `ebpf/l2fwd.c`

To test eBPF/XDP L2L3-ACL program:
- replace `<RUNTIME_CMD>` with `runtime_cmd/06_software_switching/ebpf_l2l3_acl.txt`
- replace `<EBPF_PROG>` with `ebpf/l2l3_acl.c`

To test eBPF/XDP VXLAN program:
- replace `<RUNTIME_CMD>` with `runtime_cmd/06_software_switching/ebpf_vxlan_vtep_encap.txt`
- replace `<EBPF_PROG>` with `ebpf/vxlan_vtep.c`

#### Run TRex

On the Generator machine use:

```
./ndr --stl --port 0 1 --max-iterations 20 --iter-time 60 --pdr <PDR> --pdr-error <PDR-ERROR> -o hu --force-map --profile <PROFILE> --prof-tun size=64  --verbose
```

Replace `<PROFILE>` with:
- `stl/bench.py` for L2FWD and VXLAN (encap)
- `trex_scripts/udp_1flow.py` for L2L3-ACL

### 07. Multi-queue scaling

#### Run PSA-eBPF

Assuming that isolated CPU cores on the NIC's NUMA node are within the range of 6-11,18-23, tune `--queues N` parameter to set a desired number of RX/TX queues per NIC. 

```
$ sudo -E ./setup_test.sh --queues 2 -C 6-11,18-23 -E <ENV-FILE> -c runtime_cmd/01_use_cases/l2l3_acl_routing.txt p4testdata/01_use_cases/l2l3_acl.p4
``` 

#### Run TRex


