#!/bin/bash

RESULTS=results.txt

declare -a PROGRAMS=("p4testdata/01_use_cases/bng.p4"
"p4testdata/01_use_cases/upf.p4"
"p4testdata/01_use_cases/l2l3_acl.p4")

declare -a OPTIONS=("-mcpu=v1"
  "-mcpu=v1 -mattr=+alu32"
  "-mcpu=v2"
  "-mcpu=v2 -mattr=+alu32"
  "-mcpu=v3")

declare -a P4ARGS=(""
  "--hdr2Map --xdp"
  "--hdr2Map --xdp2tc=cpumap"
  "--xdp2tc=meta")

for p4arg in "${P4ARGS[@]}"; do
  for program in "${PROGRAMS[@]}"; do
    echo "Program: ${program}, p4arg: ${p4arg}" >>$RESULTS
    for option in "${OPTIONS[@]}"; do
      sudo psabpf-ctl pipeline unload id 77
      rm -rf out
      mkdir -p out
      name=$(basename $program .p4)
      echo "Program: ${name}, p4arg: ${p4arg}, option: ${option}"
      sudo make -f ../runtime/kernel.mk COMPILERFLAGS="${option}" BPFOBJ=out/${name}.o P4FILE="$program" ARGS=-DPSA_PORT_RECIRCULATE=2 P4C=p4c-ebpf P4ARGS="${p4arg}" psa

      sudo psabpf-ctl pipeline load id 77 out/${name}.o

      if [ $? -ne 0 ]; then
        echo "Program does not load or compile"
        sudo psabpf-ctl pipeline unload id 77
        rm -rf out
        continue
      fi

      XDP_PROG_ID="$(bpftool prog show -f | grep xdp_ingress_fun | awk '{print $1}' | tr -d : | tail -n1)"
      TC_INGRESS_PROG_ID="$(bpftool prog show -f | grep tc_ingress_func | awk '{print $1}' | tr -d : | tail -n1)"

      XDP="$(bpftool prog dump xlated id ${XDP_PROG_ID} | awk '{w=$1} END{print w}' | awk '{print substr($1, 1, length($1)-1)}')"
      TC_INGRESS="$(bpftool prog dump xlated id ${TC_INGRESS_PROG_ID} | awk '{w=$1} END{print w}' | awk '{print substr($1, 1, length($1)-1)}')"

      echo "${option}: ${XDP}, ${TC_INGRESS}" >>$RESULTS

      sudo psabpf-ctl pipeline unload id 77
      rm -rf out
    done
  done
done