#!/bin/bash

if [ "x$1" = "x--help" ]; then
  echo "Script installs BMv2 software switch and its dependencies."
  echo "Execute it from directory where all dependencies can be placed."
  exit 0
fi

# Exit if any command fails
set -e
# Print executed commands
set -x

sudo apt update
sudo apt install -y automake cmake libgmp-dev \
    libpcap-dev libboost-dev libboost-test-dev libboost-program-options-dev \
    libboost-system-dev libboost-filesystem-dev libboost-thread-dev \
    libevent-dev libtool flex bison pkg-config g++ libssl-dev

function build_and_install_thrift() (
  git clone -b 0.11.0 https://github.com/apache/thrift.git thrift-0.11.0
  cd thrift-0.11.0
  ./bootstrap.sh
  ./configure --with-cpp=yes --with-c_glib=no --with-java=no --with-ruby=no --with-erlang=no --with-go=no --with-nodejs=no
  make "-j$(nproc)"
  sudo make install
  cd lib/py
  sudo python3 setup.py install
)

function build_and_install_nanomsg() (
  wget https://github.com/nanomsg/nanomsg/archive/1.0.0.tar.gz -O nanomsg-1.0.0.tar.gz
  tar -xzvf nanomsg-1.0.0.tar.gz
  rm nanomsg-1.0.0.tar.gz
  cd nanomsg-1.0.0
  mkdir build
  cd build
  cmake .. -DCMAKE_INSTALL_PREFIX=/usr
  cmake --build .
  sudo cmake --build . --target install
)

function build_and_install_bmv2() (
  git clone --recursive https://github.com/p4lang/behavioral-model.git
  cd behavioral-model/
  ./autogen.sh
  # For better performance disable logging macros
  ./configure --disable-logging-macros
  make "-j$(nproc)"
  sudo make install
)

build_and_install_thrift
build_and_install_nanomsg
build_and_install_bmv2

sudo ldconfig
