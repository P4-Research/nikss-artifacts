#!/bin/bash

function print_help() {
  # Display Help
  echo "Run benchmark tests for PSA-eBPF."
  echo "The script will configure and deploy the PSA-eBPF setup for benchmarking."
  echo
  echo "Syntax: $0 [OPTIONS] [PROGRAM]"
  echo ""
  echo "Example: $0 -E env_file -c commands.txt testdata/l2fwd.p4"
  echo ""
  echo "OPTIONS:"
  echo "-E|--env          File with environment variables for DUT."
  echo "-c|--cmd           Path to the file containing runtime configuration for P4 tables/BPF maps."
  echo "-q|--queues        Set number of RX/TX queues per NIC (default 1)."
  echo "-C|--core          CPU core that will be pinned to interfaces."
  echo "--p4args           P4ARGS for PSA-eBPF."
  echo "--target           target subsystem (default empty, possible values: psa-ebpf, p4-dpdk, bmv2-psa)"
  echo "--help             Print this message."
  echo ""
  echo "PROGRAM:           P4 file (will be compiled by PSA-eBPF and then clang) or C file (will be compiled just by clang). (mandatory)"
  echo
}

if [ "x$1" = "x--help" ]; then
  print_help
  exit 0
fi

function exit_on_error() {
      exit_code=$?
      if [ $exit_code -ne 0 ]; then
          exit $exit_code
      fi
}

function cleanup() {
    killall dpdk-pipeline
    killall psa_switch
    rm -f nohup.out out.spec out.json
    rm -f xdp_loader
    bash $OVS_REPO/utilities/ovs-ctl stop
    ip link del psa_recirc
    for intf in "${INTERFACES[@]}" ; do
        ip link set dev "$intf" xdp off
        tc qdisc del dev "$intf" clsact
    done
    make -f $P4C_REPO/backends/ebpf/runtime/kernel.mk BPFOBJ=out.o clean
    psabpf-ctl pipeline unload id 99
    rm -rf /sys/fs/bpf/*
}

NUM_QUEUES=1

POSITIONAL=()
while [[ $# -gt 0 ]]; do
  key="$1"

  case $key in
    -E|--env)
      ENV="$2"
      shift # past argument
      shift # past value
      ;;
    -C|--core)
      CORE="$2"
      shift # past argument
      shift # past value
      ;;
    -q|--queues)
      NUM_QUEUES="$2"
      shift # past argument
      shift # past value
      ;;
    -c|--cmd)
      COMMANDS_FILE="$2"
      shift # past argument
      shift # past value
      ;;
     --p4args)
      P4ARGS="$2"
      shift # past argument
      shift # past value
      ;;
     --target)
      TARGET="$2"
      shift # past argument
      shift # past value
      ;;
    *)    # unknown option
      POSITIONAL+=("$1") # save it in an array for later
      shift # past argument
      ;;
  esac
done

set -- "${POSITIONAL[@]}"

if [[ -n $1 ]]; then
    PROGRAM="$1"
fi

if [[ -z "${ENV}" ]]; then
    echo "Environment file is not provided!"
    exit 0
fi

set -o allexport
source $ENV
#set +o allexport

echo $PORT1_NAME
declare -a INTERFACES=("$PORT0_NAME" "$PORT1_NAME")

cleanup

clang -lbpf scripts/xdp_loader.c -o xdp_loader
ip link add name psa_recirc type dummy
ip link set dev psa_recirc up
echo "PSA_PORT_RECIRCULATE configuration:"
ip link show psa_recirc

declare -a RECIRC_PORT_ID=$(ip -o link | awk '$2 == "psa_recirc:" {print $1}' | awk -F':' '{print $1}')

# Trace all command from this point
#set -x

declare -a ARGS="-DPSA_PORT_RECIRCULATE=$RECIRC_PORT_ID"

function dpdk_init_pipeline() {
  echo "Running dpdk-pipeline, assuming that PCI devices $PORT0_PCI_DEV and $PORT1_PCI_DEV are bound to right driver"
  # demonise our dpdk-pipeline process
  CORE_OPTION=""
  if [ ! -z "$CORE" ]; then
    CORE_OPTION="-l $CORE"
  fi
  nohup $DPDK_PIPELINE_BIN $CORE_OPTION -a "$PORT0_PCI_DEV" -a "$PORT1_PCI_DEV" &
  # wait-for-it will crash dpdk-pipeline, so use sleep
  sleep 5
  echo "Initializing pipeline..."
  ./scripts/dpdk_pipeline_send_cmd << EOC
mempool MEMPOOL0 buffer 2304 pool 32K cache 256 cpu 1
link LINK0 dev $PORT0_PCI_DEV rxq $NUM_QUEUES 2048 MEMPOOL0 txq $NUM_QUEUES 1024 promiscuous on
link LINK1 dev $PORT1_PCI_DEV rxq $NUM_QUEUES 2048 MEMPOOL0 txq $NUM_QUEUES 1024 promiscuous on
pipeline PIPELINE0 create 0
pipeline PIPELINE0 port in 0 link LINK0 rxq 0 bsz 32
pipeline PIPELINE0 port in 1 link LINK1 rxq 0 bsz 32
pipeline PIPELINE0 port out 0 link LINK0 txq 0 bsz 32
pipeline PIPELINE0 port out 1 link LINK1 txq 0 bsz 32
pipeline PIPELINE0 build out.spec
EOC
  echo ""
}

if [[ $PROGRAM == *.p4 && $TARGET == "bmv2-psa" ]]; then
  echo "Compiling data plane program.. $PROGRAM"
  $P4C_BMV2_PSA_BIN $P4ARGS "-I$UPSTREAM_P4C_REPO/p4include/bmv2" --std p4-16 -o out.json "$PROGRAM"
  exit_on_error
  echo "Starting switch.."
  psa_switch -i "0@$PORT0_NAME" -i "1@$PORT1_NAME" out.json &
  wait-for-it 127.0.0.1:9090 -t 10
  PID=$(pgrep -o -x psa_switch)
  taskset -a -cp $CORE $PID
  echo "BMv2 PSA started!"
  if [ -n "$COMMANDS_FILE" ]; then
      tmpfile=$(mktemp)
      cat $COMMANDS_FILE | envsubst > $tmpfile
      psa_switch_CLI < $tmpfile
      rm $tmpfile
      echo -e "\nTable entries successfully installed!"
  fi
elif [[ $PROGRAM == *.p4 && $TARGET == "p4-dpdk" ]]; then
  echo "Compiling data plane program.. $PROGRAM"
  $P4C_DPDK_BIN $P4ARGS "-I$UPSTREAM_P4C_REPO/p4include/dpdk" --arch psa -o out.spec "$PROGRAM"
  exit_on_error
  dpdk_init_pipeline
  echo "Installing table entries.. Looking for $COMMANDS_FILE"
  if [ -n "$COMMANDS_FILE" ]; then
    ./scripts/dpdk_pipeline_send_cmd < "$COMMANDS_FILE"
    echo -e "\nTable entries successfully installed!"
  else
    echo "File with table entries not provided"
  fi
  exit 0
elif [[ $PROGRAM == *.p4 ]]; then
  echo "Compiling data plane program.. $PROGRAM"
  make -f $P4C_REPO/backends/ebpf/runtime/kernel.mk BPFOBJ=out.o \
      P4FILE=$PROGRAM ARGS="$ARGS" P4ARGS="$P4ARGS" psa
  exit_on_error
  psabpf-ctl pipeline load id 99 out.o
  exit_on_error
elif [[ $PROGRAM == *.c && $TARGET == "psa-ebpf" ]]; then
  echo "Compiling data plane program.. $PROGRAM"
  make -f $P4C_REPO/backends/ebpf/runtime/kernel.mk BPFOBJ=out.o ARGS="$ARGS" ebpf CFILE=$PROGRAM
  exit_on_error
  psabpf-ctl pipeline load id 99 out.o
  exit_on_error
elif [[ $PROGRAM == *.c ]]; then
  echo "Compiling data plane program.. $PROGRAM"
  make -f $P4C_REPO/backends/ebpf/runtime/kernel.mk BPFOBJ=out.o ARGS="$ARGS" ebpf CFILE=$PROGRAM
  bpftool prog loadall out.o /sys/fs/bpf/prog
  exit_on_error
elif [[ $PROGRAM == "openvswitch" ]]; then
  echo "Running Open vSwitch.."
  bash $OVS_REPO/utilities/ovs-ctl start
fi

for intf in "${INTERFACES[@]}" ; do
  # Disable trash traffic
  sysctl -w net.ipv6.conf."$intf".disable_ipv6=1
  sysctl -w net.ipv6.conf."$intf".autoconf=0
  sysctl -w net.ipv6.conf."$intf".accept_ra=0

  ifconfig "$intf" promisc
  ifconfig "$intf" mtu 1500 up
  ethtool -L "$intf" combined $NUM_QUEUES
  ethtool -G "$intf" tx 4096
  ethtool -G "$intf" rx 4096
  ethtool -K "$intf" txvlan off
  ethtool -K "$intf" rxvlan off
  ethtool -A "$intf" rx off tx off

  if [[ $PROGRAM == *.p4 && $TARGET == "psa-ebpf" ]]; then
      psabpf-ctl pipeline add-port id 99 "$intf"
  elif [[ $PROGRAM == *.c && $TARGET == "psa-ebpf" ]]; then
      psabpf-ctl pipeline add-port id 99 "$intf"
  elif [[ $PROGRAM == *.c ]]; then
      ./xdp_loader "$intf"
  fi

  # by default, pin IRQ to 3rd CPU core
  bash scripts/set_irq_affinity.sh $CORE "$intf"
done

if [[ $TARGET == "p4-dpdk" || $TARGET == "bmv2-psa"  ]]; then
    # no need to proceed further
    exit 0
fi

echo "Installing table entries.. Looking for $COMMANDS_FILE"
if [[ -n "$COMMANDS_FILE" ]]; then
   cat $COMMANDS_FILE
   bash $COMMANDS_FILE
   echo -e "\nTable entries successfully installed!"
else
   echo "File with table entries not provided"
fi

echo -e "\n\nDumping network configuration:"
# dump network configuration
for intf in "${INTERFACES[@]}" ; do
  ip link show "$intf"
done

if [[ $PROGRAM == "openvswitch" ]]; then
    # no need to proceed further
    exit 0
fi

echo -e "\n\nDumping BPF setup:"
bpftool net show

XDP_HELPER_PROG="$(bpftool prog show -f | grep xdp_func | awk '{print $1}' | tr -d : | tail -n1)"
XDP_INGRESS_PROG="$(bpftool prog show -f | grep xdp_ingress_fun | awk '{print $1}' | tr -d : | tail -n1)"
XDP_EGRESS_PROG="$(bpftool prog show -f | grep xdp_egress_fun | awk '{print $1}' | tr -d : | tail -n1)"

TC_EGRESS_PROG_ID="$(bpftool prog show -f | grep tc_egress_func | awk '{print $1}' | tr -d : | tail -n1)"
TC_INGRESS_PROG_ID="$(bpftool prog show -f | grep tc_ingress_func | awk '{print $1}' | tr -d : | tail -n1)"

XLATED_XDP_HELPER="$(bpftool prog dump xlated id "$XDP_HELPER_PROG" | grep -v ";" | wc -l)"
JITED_XDP_HELPER="$(bpftool prog dump jited id "$XDP_HELPER_PROG" | grep -v ";" | wc -l)"

XLATED_XDP_INGRESS="$(bpftool prog dump xlated id "$XDP_INGRESS_PROG" | grep -v ";" | wc -l)"
JITED_XDP_INGRESS="$(bpftool prog dump jited id "$XDP_INGRESS_PROG" | grep -v ";" | wc -l)"

XLATED_XDP_EGRESS="$(bpftool prog dump xlated id "$XDP_EGRESS_PROG" | grep -v ";" | wc -l)"
JITED_XDP_EGRESS="$(bpftool prog dump jited id "$XDP_EGRESS_PROG" | grep -v ";" | wc -l)"

XLATED_TC_INGRESS="$(bpftool prog dump xlated id "$TC_INGRESS_PROG_ID" | grep -v ";" | wc -l)"
JITED_TC_INGRESS="$(bpftool prog dump jited id "$TC_INGRESS_PROG_ID" | grep -v ";" | wc -l)"

XLATED_TC_EGRESS="$(bpftool prog dump xlated id "$TC_EGRESS_PROG_ID" | grep -v ";" | wc -l)"
JITED_TC_EGRESS="$(bpftool prog dump jited id "$TC_EGRESS_PROG_ID" | grep -v ";" | wc -l)"

STACK_SIZE="$(llvm-objdump -S -no-show-raw-insn out.o | grep "r10 -" | awk '{print $7}' | sort -n | tail -n1 | tr -d ")")"

echo -e "Summary of eBPF programs:"
echo -e "BPF stack size = "$STACK_SIZE""
echo -e "# of BPF insns"
echo -e "\tXDP helper:"
echo -e "\t\txlated: "$XLATED_XDP_HELPER""
echo -e "\t\tjited: "$JITED_XDP_HELPER""
echo -e "\tXDP ingress:"
echo -e "\t\txlated: "$XLATED_XDP_INGRESS""
echo -e "\t\tjited: "$JITED_XDP_INGRESS""
echo -e "\tXDP egress:"
echo -e "\t\txlated: "$XLATED_XDP_EGRESS""
echo -e "\t\tjited: "$JITED_XDP_EGRESS""
echo -e "\tTC ingress:"
echo -e "\t\txlated: "$XLATED_TC_INGRESS""
echo -e "\t\tjited: "$JITED_TC_INGRESS""
echo -e "\tTC egress:"
echo -e "\t\txlated: "$XLATED_TC_EGRESS""
echo -e "\t\tjited: "$JITED_TC_EGRESS""
