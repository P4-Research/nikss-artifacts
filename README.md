# NIKSS artifact

This repository contains scripts for the CoNEXT'22 artifact evaluation of paper entitled "A novel programmable software datapath for Software-Defined Networking". The scripts in this repository can be used to produce the performance data (throughput, latency, CPU cycles, number of instructions) for the following figures:
* Figure 3: Packet forwarding rate of NIKSS-TC (left) and NIKSS-XDP (right) with only pipeline-aware optimization enabled for different packet sizes
* Table 2: The in-depth performance analysis of test programs
* Figure 4: The cost of different P4 match kinds measured in the throughput rate and average CPU cycles per packet over a baseline depending on the number of table entries.
* Figure 5: The cost of PSA externs measured in average CPU cycles per packet over a baseline program
* Figure 6: The throughput of test programs  and latency distribution by percentiles for L2L3-ACL and 0.8 MPPS of the offered load (right) for NIKSS and P4- DPDK.
* Figure 7: The throughput of test programs and latency distribution by percentiles for L2L3-ACL and 0.8 MPPS of the offered load for kernel datapaths.

The `results/` directory contains Excel files that can be used to calculate end results and generate plots (plot.xslx). 

> NOTE: Originally, we used Google Sheets to calculate results, but we converted them to XSLX files. If you meet issues with Excel files, please use Sheets files [[link](https://drive.google.com/drive/folders/1L0RbuOE3CkqqAHmcYW66-tz3b1M58TNB?usp=sharing)] as a backup.
> plots.xslx is originally an Excel file and you should not expect issues when generating plots.

## Hardware dependencies

The tests require two machine connected back-to-back: the Generator machine and the Device Under Test (DUT) machine.  The two machines should be equipped with a NIC with at least 2 ports available and with support for DPDK and XDP in native mode.

## Software dependencies

The tests we done on Ubuntu 20.04 with installed kernel 5.11.3. The main software requirements are as follows:
* Linux kernel >=5.8
* TRex >=2.92
* clang 10 
* bpftool
* DPDK 21.11.0

## Generator machine

Steps to follow to prepare the generator machine. 

### Install required software

### Configure TRex

Use the below script to setup DPDK ports for TRex.

```
$ cd trex/v2.92/
$ sudo ./dpdk_setup_ports.py -i
```

You will also need `HDRHistorgram` library for latency measurements:

```
$ pip install hdrhistogram
```

## DUT machine

Steps to follow to prepare the DUT machine. 

### Hardware settings & OS configuration

In order to make tests as stable and reproducible as possible and to minimize interference from system activity, the following configuration was done. Note that the same configuration is used for both NIKSS in-kernel tests and P4-dpdk userspace tests. All our tests we done with DUT kernel version v5.11.3.
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

### Build NIKSS

Make sure this repository has been cloned recursivly. Otherwise invoke:
```
git submodule update --init --recursive
```
Go to the p4c-ebpf-psa directory andf follow the steps in the README to install NIKSS on DUT machine. 

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

To check the basic usage of `setup_test.sh` run:

```
$ ./setup_test.sh --help
```

### 01. Packet forwarding rate (figure 3)

Run NIKSS.

- L2FWD program on DUT machine:

```
sudo -E ./setup_test.sh -C 6 --target psa-ebpf --p4args "--hdr2Map --max-ternary-masks 3 --xdp --pipeline-opt" -E <ENV-FILE> -c runtime_cmd/00_warmup/l2fwd.txt p4testdata/00_warmup/l2fwd.p4
```

- L2L3-ACL program and routing rules on DUT machine: 

```
sudo -E ./setup_test.sh -C 6 --target psa-ebpf --p4args "--hdr2Map --max-ternary-masks 3 --xdp --pipeline-opt" -E <ENV-FILE> -c runtime_cmd/01_use_cases/l2l3_acl_routing.txt p4testdata/01_use_cases/l2l3_acl.p4
```

- BNG (encap) program on DUT machine:

```
sudo -E ./setup_test.sh -C 6 --target psa-ebpf --p4args "--hdr2Map --max-ternary-masks 3 --xdp --pipeline-opt" -E <ENV-FILE> -c runtime_cmd/01_use_cases/bng_dl.txt p4testdata/01_use_cases/bng.p4
```

- BNG (decap) program on DUT machine:

```
sudo -E ./setup_test.sh -C 6 --target psa-ebpf --p4args "--hdr2Map --max-ternary-masks 3 --xdp --pipeline-opt" -E <ENV-FILE> -c runtime_cmd/01_use_cases/bng_ul.txt p4testdata/01_use_cases/bng.p4
```

- UPF (encap) program on DUT machine:

```
sudo -E ./setup_test.sh -C 6 --target psa-ebpf --p4args "--hdr2Map --max-ternary-masks 3 --xdp --pipeline-opt" -E <ENV-FILE> -c runtime_cmd/01_use_cases/upf_dl.txt p4testdata/01_use_cases/upf.p4
```

- UPF (decap) program on DUT machine:

```
sudo -E ./setup_test.sh -C 6 --target psa-ebpf --p4args "--hdr2Map --max-ternary-masks 3 --xdp --pipeline-opt" -E <ENV-FILE> -c runtime_cmd/01_use_cases/upf_ul.txt p4testdata/01_use_cases/upf.p4
```


#### Run TRex

For each program, run the NDR script and tune `size=`/`packet_len=` parameter accordingly (use 128, 256, 512, 1024, 1518 packet sizes).

```
./ndr --stl --port 0 1 --max-iterations 20 -t 60 --pdr <PDR> --pdr-error 0.05 -o hu --force-map <TREX_ARGS> --verbose
```

`<TREX_ARGS>` values:
- for UPF: 
  - uplink: `--profile trex_scripts/upf_ul.py --prof-tun packet_len=X`
  - downlink: `--profile stl/bench.py --prof-tun packet_len=X` (due to MTU limit set `packet_len` to 1472 instead of 1512)
- for L2L3-ACL: `--profile trex_scripts/udp_1flow.py --prof-tun packet_len=X`
- for BNG:
  - uplink: `--profile trex_scripts/bng_ul.py --prof-tun packet_len=X`
  - downlink: `--profile stl/bench.py --prof-tun packet_len=X` (due to MTU limit set `packet_len` to 1496 instead of 1512)
- for L2FWD: `--profile stl/bench.py --prof-tun --size=X`


### 02. End-to-end performance (table 2)

#### DUT

```
$ sudo -E ./setup_test.sh -C 6 --target psa-ebpf -E <ENV-FILE> --p4args <P4ARGS> -c <SCRIPT> <P4-PROGRAM>
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

`$ ./ndr --stl --port 0 1 --max-iterations 20 -t 60  --pdr <PDR> --pdr-error 0.05 -o hu --force-map --profile <PROFILE>`

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

### 03. Microbenchmarking: the cost of PSA externs (figure 5)

#### DUT

```
$ sudo -E ./setup_test.sh -C 6 --target psa-ebpf --p4args "--xdp --pipeline-opt --hdr2Map --max-ternary-masks 3" -E <ENV-FILE> -c <SCRIPT> <P4-PROGRAM>
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

### 04. Microbenchmarking: P4 Table lookup time (figure 4)

#### DUT

```
$ sudo -E ./setup_test.sh -C 6 --target psa-ebpf --p4args "--xdp --pipeline-opt --hdr2Map --max-ternary-masks 11" -E <ENV-FILE> -c <SCRIPT> <P4-PROGRAM>
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

### 05. Comparison with other host-based P4 platforms (throughput, figure 6)

#### Run P4-DPDK

```
$ sudo -E ./setup_test.sh -C 6 --target p4-dpdk -E env/pllab.env <PROGRAM>
```

> **Note!** We observed occasional failures due to `Error: Connectivity initialization failed (0)`. In that case, retry running `setup_test.sh`

Replace `<PROGRAM>` with:
- `p4testdata/05_p4_targets/l2fwd.p4` for L2FWD
- `p4testdata/05_p4_targets/upf_dpdk.p4` for UPF
- `p4testdata/05_p4_targets/l2l3_acl_simple.p4` for L2L3-ACL
- `p4testdata/05_p4_targets/bng_dpdk.p4` for BNG

P4-DPDK uses `telnet` to install table entries. After running `setup_test.sh`, install table entries for P4-DPDK using:

```
$ ./scripts/dpdk_pipeline_send_cmd < <RUNTIME_CMD>
```

Replace `<RUNTIME_CMD>` with:
- `runtime_cmd/05_p4_targets/dpdk_upf/dpdk_upf_dl.txt` for UPF (encap)
- `runtime_cmd/05_p4_targets/dpdk_upf/dpdk_upf_ul.txt` for UPF (decap)
- `runtime_cmd/05_p4_targets/dpdk_bng_dl.txt` for BNG (encap)
- `runtime_cmd/05_p4_targets/dpdk_bng_ul.txt` for BNG (decap)
- `runtime_cmd/05_p4_targets/dpdk_l2l3_acl_routing.txt` for L2L3-ACL
- `runtime_cmd/05_p4_targets/dpdk_l2fwd.txt` for L2FWD

### Run PSA-eBPF

TBD

### 05. Comparison with other host-based P4 platforms (latency, figure 6)

#### Run P4-DPDK and NIKSS

Use `setup_test.sh` in the same way as for the previous scenario.

#### Run TRex 

Run TRex with `--hdrh` flag and use the Python script from trex_scripts as follows:

```
$ sudo ./t-rex -c <CORE> -i --hdrh
$ PYTHONPATH=./automation/trex_control_plane/interactive/trex/examples/stl/ python ./psa-ebpf-artifacts/trex_scripts/l2l3_latency.py
```

### 06. Comparison with other software switches (throughput, figure 7)

#### Run NIKSS

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

### 06. Comparison with other software switches (latency, figure 7)

#### Run NIKSS (TC)

```
$ sudo -E ./setup_test.sh -C 6 --p4args "--hdr2Map --max-ternary-masks 3" -E <ENV-FILE> -c runtime_cmd/06_software_switching/l2l3_acl_latency.txt p4testdata/06_software_switching/l2l3_acl_simple.p4
```

#### Run NIKSS (XDP)

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

#### Run TRex 

Run TRex with `--hdrh` flag and use the Python script from trex_scripts as follows:

```
$ sudo ./t-rex -c <CORE> -i --hdrh
$ PYTHONPATH=./automation/trex_control_plane/interactive/trex/examples/stl/ python ./psa-ebpf-artifacts/trex_scripts/l2l3_latency.py
```


### 07. Multi-queue scaling (extra)

#### Run NIKSS

Assuming that isolated CPU cores on the NIC's NUMA node are within the range of 6-11,18-23, tune `--queues N` parameter to set a desired number of RX/TX queues per NIC. 

```
$ sudo -E ./setup_test.sh --p4args "--xdp --hdr2Map --max-ternary-masks 3 --pipeline-opt" --target psa-ebpf --queues N -C 6-11 -E <ENV-FILE> -c runtime_cmd/01_use_cases/l2l3_acl_routing.txt p4testdata/01_use_cases/l2l3_acl.p4
``` 

#### Run TRex

Replace X with 64 or 1508. 

```
$ ./ndr --stl --port 0 1 --max-iterations 20 --iter-time 60 --pdr 0.1 --pdr-error 0.05 -o hu --force-map --profile stl/bench.py --prof-tun size=X,vm=tuple --verbose
```


