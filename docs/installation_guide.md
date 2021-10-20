# Generator machine

## Install TRex

Follow the steps below to download TRex to your machine. 

```bash
$ mkdir -p trex
$ cd trex/
$ wget --no-cache https://trex-tgn.cisco.com/trex/release/latest
$ tar -xzvf latest
```

For further information refer to [the TRex manual](https://trex-tgn.cisco.com/trex/doc/trex_manual.html). 

## Install netperf

```bash
$ mkdir -p netperf
$ curl -LO https://github.com/HewlettPackard/netperf/archive/netperf-2.7.0.tar.gz
$ tar -xzf netperf-2.7.0.tar.gz
$ mv netperf-netperf-2.7.0/ netperf-2.7.0
$ cd netperf-2.7.0 && ./configure
$ make
$ [sudo] make install
```