#!/bin/bash

function print_help() {
  echo -e "Usage: "
  echo -e "\t $0 INTF_LIST P4_PROGRAM"
  echo -e "\t $0 --help"
  echo -e "Example: "
  echo -e "\t $0 ens1f0,ens1f1 testdata/l2fwd.p4"
  echo -e "\nWill configure eBPF environment, compile P4 program, run and report CPU profiling and usage statistics."
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
    ip link del psa_recirc
    for intf in ${INTERFACES//,/ } ; do
        ip link set dev "$intf" xdp off
        tc qdisc del dev "$intf" clsact
    done
    make -f ../runtime/kernel.mk BPFOBJ=out.o clean
    psabpf-ctl pipeline unload id 99
    rm -rf /sys/fs/bpf/*
}

if (( $# != 2 )); then
    >&2 echo -e "Illegal number of arguments! \n"
    print_help
    exit 1
fi

declare -a INTERFACES=$1

cleanup
#trap cleanup EXIT

ip link add name psa_recirc type dummy
ip link set dev psa_recirc up
echo "PSA_PORT_RECIRCULATE configuration:"
ip link show psa_recirc

declare -a RECIRC_PORT_ID=$(ip -o link | awk '$2 == "psa_recirc:" {print $1}' | awk -F':' '{print $1}')

# Trace all command from this point
#set -x

echo "Compiling data plane program.."
declare -a P4PROGRAM=$(find "$2" -maxdepth 1 -type f -name "*.p4")
declare -a ARGS="-DPSA_PORT_RECIRCULATE=$RECIRC_PORT_ID"

if [ -n "$P4PROGRAM" ]; then
  echo "Found P4 program: $P4PROGRAM"
  make -f ../runtime/kernel.mk BPFOBJ=out.o \
      P4FILE=$P4PROGRAM ARGS="$ARGS" P4ARGS="$P4ARGS" psa
  exit_on_error
  psabpf-ctl pipeline load id 99 out.o
  exit_on_error
else
  declare -a CFILE=$(find "$2" -maxdepth 1 -type f -name "*.c")
  if [ -z "$CFILE" ]; then
    echo "Neither P4 nor C file found under path $2"
    exit 1
  fi
  echo "Found C file: $CFILE"
  make -f ../runtime/kernel.mk BPFOBJ=out.o ARGS="$ARGS" ebpf CFILE=$CFILE
  bpftool prog loadall out.o /sys/fs/bpf/prog
  exit_on_error
fi

for intf in ${INTERFACES//,/ } ; do
  # Disable trash traffic
  sysctl -w net.ipv6.conf."$intf".disable_ipv6=1
  sysctl -w net.ipv6.conf."$intf".autoconf=0
  sysctl -w net.ipv6.conf."$intf".accept_ra=0

  ifconfig "$intf" promisc
  ethtool -L "$intf" combined 1
  ethtool -G "$intf" tx 4096
  ethtool -G "$intf" rx 4096
  ethtool -K "$intf" txvlan off
  ethtool -K "$intf" rxvlan off

  # TODO: these commands are used if an eBPF program written in C is being tested.
  #  We should refactor this script.
  #bpftool net attach xdp pinned /sys/fs/bpf/prog/xdp_xdp-ingress dev "$intf" overwrite
  #tc qdisc add dev "$intf" clsact
  #tc filter add dev "$intf" ingress bpf da fd /sys/fs/bpf/prog/classifier_tc-ingress
  #tc filter add dev "$intf" egress bpf da fd /sys/fs/bpf/prog/classifier_tc-egress

  psabpf-ctl pipeline add-port id 99 "$intf"

  # by default, pin IRQ to 3rd CPU core
  bash scripts/set_irq_affinity.sh 2 "$intf"
done

echo "Installing table entries.. Looking for $2/commands.txt"
if [ -n "$2/commands.txt" ]; then
   cat $2/commands.txt
   bash $2/commands.txt
   echo "Table entries successfully installed!"
else
   echo "File with table entries not provided"
fi

echo -e "Dumping network configuration:"
# dump network configuration
for intf in ${INTERFACES//,/ } ; do
  ip link show "$intf"
done

echo -e "Dumping BPF setup:"
bpftool net show

XDP_PROG_ID="$(bpftool prog show -f | grep xdp_func | awk '{print $1}' | tr -d : | tail -n1)"
TC_EGRESS_PROG_ID="$(bpftool prog show -f | grep tc_egress_func | awk '{print $1}' | tr -d : | tail -n1)"
TC_INGRESS_PROG_ID="$(bpftool prog show -f | grep tc_ingress_func | awk '{print $1}' | tr -d : | tail -n1)"

XLATED_XDP="$(bpftool prog dump xlated id "$XDP_PROG_ID" | grep -v ";" | wc -l)"
JITED_XDP="$(bpftool prog dump jited id "$XDP_PROG_ID" | grep -v ";" | wc -l)"

XLATED_TC_INGRESS="$(bpftool prog dump xlated id "$TC_INGRESS_PROG_ID" | grep -v ";" | wc -l)"
JITED_TC_INGRESS="$(bpftool prog dump jited id "$TC_INGRESS_PROG_ID" | grep -v ";" | wc -l)"

XLATED_TC_EGRESS="$(bpftool prog dump xlated id "$TC_EGRESS_PROG_ID" | grep -v ";" | wc -l)"
JITED_TC_EGRESS="$(bpftool prog dump jited id "$TC_EGRESS_PROG_ID" | grep -v ";" | wc -l)"

XLATED=$(( $XLATED_XDP + $XLATED_TC_INGRESS + $XLATED_TC_EGRESS ))
JITED=$(( $JITED_XDP + $JITED_TC_INGRESS + $JITED_TC_EGRESS  ))

STACK_SIZE="$(llvm-objdump -S -no-show-raw-insn out.o | grep "r10 -" | awk '{print $7}' | sort -n | tail -n1 | tr -d ")")"

echo -e "Summary of eBPF programs:"
echo -e "BPF stack size = "$STACK_SIZE""
echo -e "# of BPF insns"
echo -e "\txlated: "$XLATED""
echo -e "\tjited: "$JITED""
