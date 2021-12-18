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
sudo ip netns exec netperf-client netperf -H 10.0.0.2 -p 5555 -t TCP_RR -l 180 -- -o min_latency,max_latency,mean_latency,transaction_rate,p50_latency,p90_latency,p99_latency
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

### Prerequisites

```
$ sudo apt install -y expect wait-for-it
```

### Build PSA-eBPF

Follow the steps from the [psa-ebpf-psa](https://github.com/P4-Research/p4c-ebpf-psa) repository to install PSA-eBPF on DUT machine. 

### Build P4-DPDK

To build the P4-DPDK target on the DUT machine, proceed as follows:
-  Compile the p4c-dpdk compiler by cloning the [p4c](https://github.com/p4lang/p4c) mainstream repository and following its instructions to build it from source. Only build the p4c-dpdk compiler by indicating *p4c-dpdk* as the target:
```
mkdir build
cd build
cmake ..
make -j4 p4c-dpdk
```
**Do not run** ***'make install'*** otherwise the previously installed PSA-EBPF compiler will be overwritten.
Set the `UPSTREAM_P4C_REPO` environment variable to the absolute path of the p4c repository.
-  Download [DPDK 21.11.0](https://fast.dpdk.org/rel/dpdk-21.11.tar.xz) and install the required dependencies as indicated in the [DPDK documentatio](https://doc.dpdk.org/guides/linux_gsg/sys_reqs.html#compilation-of-the-dpdk). Build DPDK along with DPDK Software Switch (SWX) pipeline application as follows (a patch needs to be applied to fix a blocking issue):
```
tar xf dpdk-21.11.tar.xz 
cd dpdk-21.11
patch -p1 < ${PSA-EBPF-ARTIFACTS}/patches/dpdk-fix-annotation-checks.patch
meson -Dexamples=pipeline  build
ninja -C build
ninja -C build install
```
Set the DPDK_PIPELINE_BIN environment variable to the absolute path of the dpdk-pipeline application.

### Build BMv2

To build and install BMv2 execute `script/setup_bmv2.sh` from directory where you want place source code (e.g. home directory).

To build P4 compiler for BMv2 (if you build p4-dpdk before you can execute only last instruction from `build` directory):
```shell
git clone --recursive https://github.com/p4lang/p4c.git
cd p4c
mkdir build
cd build
cmake ..
make "-j$(nproc)" p4c-bm2-psa
```

**Do not run** ***'make install'*** otherwise the previously installed PSA-EBPF compiler will be overwritten.

Set the `UPSTREAM_P4C_REPO` environment variable to the absolute path of the p4c repository.

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

Run PSA-eBPF.

- L2FWD program on DUT machine:

```
sudo -E ./setup_test.sh -C 6 --p4args "--hdr2Map --max-ternary-masks 3 --xdp --pipeline-opt" -E <ENV-FILE> -c runtime_cmd/00_warmup/l2fwd.txt p4testdata/00_warmup/l2fwd.p4
```

- L2L3-ACL program and routing rules on DUT machine: 

```
sudo -E ./setup_test.sh -C 6 --p4args "--hdr2Map --max-ternary-masks 3 --xdp --pipeline-opt" -E <ENV-FILE> -c runtime_cmd/01_use_cases/l2l3_acl_routing.txt p4testdata/01_use_cases/l2l3_acl.p4
```

- BNG (encap) program on DUT machine:

```
sudo -E ./setup_test.sh -C 6 --p4args "--hdr2Map --max-ternary-masks 3 --xdp --pipeline-opt" -E <ENV-FILE> -c runtime_cmd/01_use_cases/bng_dl.txt p4testdata/01_use_cases/bng.p4
```

- BNG (decap) program on DUT machine:

```
sudo -E ./setup_test.sh -C 6 --p4args "--hdr2Map --max-ternary-masks 3 --xdp --pipeline-opt" -E <ENV-FILE> -c runtime_cmd/01_use_cases/bng_ul.txt p4testdata/01_use_cases/bng.p4
```

- UPF (encap) program on DUT machine:

```
sudo -E ./setup_test.sh -C 6 --p4args "--hdr2Map --max-ternary-masks 3 --xdp --pipeline-opt" -E <ENV-FILE> -c runtime_cmd/01_use_cases/upf_dl.txt p4testdata/01_use_cases/upf.p4
```

- UPF (decap) program on DUT machine:

```
sudo -E ./setup_test.sh -C 6 --p4args "--hdr2Map --max-ternary-masks 3 --xdp --pipeline-opt" -E <ENV-FILE> -c runtime_cmd/01_use_cases/upf_ul.txt p4testdata/01_use_cases/upf.p4
```


#### Run TRex

For each program, run the NDR script and tune `size=` parameter accordingly (use 64, 128, 256, 512, 1024, 1518 packet sizes).

```
./ndr --stl --port 0 1 --max-iterations 20 -t 60 --pdr <PDR> --pdr-error <PDR-ERROR> -o hu --force-map --profile <PROFILE> --prof-tun size=X  --verbose
```

`<PROFILE>` values:
- for UPF: 
  - uplink: `--profile trex_scripts/upf_ul.py`
  - downlink: `--profile stl/bench.py`
- for L2L3-ACL: `--profile trex_scripts/udp_1flow.py --prof-tun packet_len=X`
- for BNG:
  - uplink: `--profile trex_scripts/bng_ul.py`
  - downlink: `--profile stl/bench.py`
- for L2FWD: `--profile stl/bench.py`


### 02. End-to-end performance

#### DUT

```
$ sudo -E ./setup_test.sh -C 6 -E <ENV-FILE> --p4args <P4ARGS> -c <SCRIPT> <P4-PROGRAM>
```

Replacements:
- for UPF uplink (decap) testing replace `<SCRIPT>` with `runtime_cmd/01_use_cases/upf_ul.txt` and `<P4-PROGRAM` with `p4testdata/01_use_cases/upf.p4`
- for UPF downlink (encap) testing replace `<SCRIPT>` with `runtime_cmd/01_use_cases/upf_dl.txt` and `<P4-PROGRAM` with `p4testdata/01_use_cases/upf.p4`
- for L2L3-ACL testing replace `<SCRIPT>` with `runtime_cmd/01_use_cases/l2l3_acl_routing.txt` and `<P4-PROGRAM` with `p4testdata/01_use_cases/l2l3_acl.p4`

Enabling optimizations:
- "none" - replace `<P4ARGS>` with `"--hdr2Map --max-ternary-masks 3"`
- "+O1" - replace `<P4ARGS>` with `"--xdp --hdr2Map --max-ternary-masks 3"`
- "O1 +O2" - replace `<P4ARGS>` with `"--xdp --pipeline-opt --hdr2Map --max-ternary-masks 3"`
- "O1,O2 +O3" - replace `<P4ARGS>` with `"--xdp --pipeline-opt --table-caching --hdr2Map --max-ternary-masks 3"`. This configuration applies All optimizations.

#### Generator

`$ ./ndr --stl --port 0 1 --max-iterations 20 -t 60  --pdr <PDR> --pdr-error <PDR-ERROR> -o hu --force-map --profile <PROFILE>`

`<PROFILE>` values:
- for UPF: 
  - uplink: `--profile trex_scripts/upf_ul.py --prof-tun packet_len=64`
  - downlink: `--profile stl/bench.py --prof-tun size=64`
- for L2L3-ACL: `--profile trex_scripts/udp_1flow.py`
- for BNG:
  - uplink: `--profile trex_scripts/bng_ul.py`
  - downlink: `--profile stl/bench.py --prof-tun size=64`
- for L2FWD: `--profile stl/bench.py --prof-tun size=64`

#### Measuring total CPU cycles

On the DUT machine use:

```
$ sudo bpftool prog profile id <PROG-ID> cycles
```

You can retrieve `<PROG-ID>` using:

```
$ sudo bpftool prog show -f
```

You should run the measurement for each BPF program participating in the packet processing:
- If none or only O2, O3 optimizations are enabled, measure CPU cycles for the following programs: `xdp_func`, `tc_ingress_func`, `tc_egress_func`
- If O1 (XDP acceleration) is enabled, measure CPU cycles for: `xdp_ingress_fun`, `xdp_egress_func`

Then, on the Generator machine run a single iteration with line-rate:

```
$ ./ndr --stl --max-iterations 20 -t 60 --port 0 1 --pdr 0.1 --pdr-error 0.05 -o hu --force-map --profile <PROFILE>  --verbose
```

Once it's finished, stop `bpftool prog profile` on the DUT machine. The output will be as follows:

```
$ sudo bpftool prog profile id 6953 cycles

          47497793 run_cnt             
       68764695258 cycles
```

To get the CPU cycles per packet, divide `cycles` by `run_cnt`. 

### 03. Microbenchmarking: the cost of PSA externs

#### DUT

```
$ sudo -E ./setup_test.sh -C 6 --p4args "--xdp --pipeline-opt --hdr2Map --max-ternary-masks 3" -E <ENV-FILE> -c <SCRIPT> <P4-PROGRAM>
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

#### DUT

```
$ sudo -E ./setup_test.sh -C 6 --p4args "--xdp --pipeline-opt --hdr2Map --max-ternary-masks 11" -E <ENV-FILE> -c <SCRIPT> <P4-PROGRAM>
```

Replace `<P4-PROGRAM>` with: 
- `p4testdata/04_tables/baseline.p4` to measure baseline program
- `p4testdata/04_tables/exact.p4` to test exact match
- `p4testdata/04_tables/lpm.p4` to test LPM
- `p4testdata/04_tables/ternary.p4` to test ternary match

Replace `<SCRIPT>` with: 
- nothing to measure the baseline program (remove `-c` flag)
- `X-entries` (replace X with number of entries) under `runtime_cmd/04_tables/exact` to test exact match 
- `X-entries` (replace X with number of entries) under `runtime_cmd/04_tables/lpm` to test LPM match. Use `runtime_cmd/04_tables/lpm/1000-entries-10-prefixes` to test scenario with 10 LPM prefixes. 
- `X-entries` (replace X with number of entries) under `runtime_cmd/04_tables/ternary` to test ternary match. Use `runtime_cmd/04_tables/ternary/1000-entries-10-masks` to test scenario with 10 ternary masks.  

### 05. Comparison with other host-based P4 platforms

#### Run BMv2 

```
$ sudo -E ./setup_test.sh --target bmv2-psa -C 6 -E <ENV-FILE> -c <SCRIPT> <PROGRAM>
```

Replace `<SCRIPT>` with:
- `runtime_cmd/05_p4_targets/bmv2_l2fwd.txt` for L2FWD

Replace `<PROGRAM>` with:
- `p4testdata/05_p4_targets/l2fwd.p4` for L2FWD
### 06. Comparison with other software switches (throughput)

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

### 06. Comparison with other software switches (latency)

#### Run PSA-eBPF (TC)

```
$ sudo -E ./setup_test.sh -C 6 --p4args "--hdr2Map --max-ternary-masks 3" -E <ENV-FILE> -c runtime_cmd/06_software_switching/l2l3_acl_latency.txt p4testdata/06_software_switching/l2l3_acl_simple.p4
```

#### Run PSA-eBPF (XDP)

```
$ sudo -E ./setup_test.sh -C 6 --p4args "--xdp --hdr2Map --max-ternary-masks 3 --pipeline-opt" -E <ENV-FILE> -c runtime_cmd/06_software_switching/l2l3_acl_latency.txt p4testdata/06_software_switching/l2l3_acl_simple.p4
```

#### Run OVS

```
$ sudo -E ./setup_test.sh -C 6 -E <ENV-FILE> -c runtime_cmd/06_software_switching/ovs_l2l3_acl_latency.sh  openvswitch
```

#### Run native eBPF/XDP

```
$ sudo -E ./setup_test.sh -C 6 -E env/pllab.env -c runtime_cmd/06_software_switching/ebpf_l2l3_latency.txt ebpf/l2l3_acl.c
```

#### Run Netperf

On Generator machine:

```
$ sudo ip netns exec netperf-client netperf -H 10.0.0.2 -p 5555 -t TCP_RR -l 180 -- -o min_latency,max_latency,mean_latency,transaction_rate,p50_latency,p90_latency,p99_latency
```

### 07. Multi-queue scaling

#### Run PSA-eBPF

Assuming that isolated CPU cores on the NIC's NUMA node are within the range of 6-11,18-23, tune `--queues N` parameter to set a desired number of RX/TX queues per NIC. 

```
$ sudo -E ./setup_test.sh --queues 2 -C 6-11,18-23 -E <ENV-FILE> -c runtime_cmd/01_use_cases/l2l3_acl_routing.txt p4testdata/01_use_cases/l2l3_acl.p4
``` 

#### Run TRex


