#!/bin/bash
cd zlib-1.2.8.dfsg
make clean
CHOST=arm-linux-gnueabihf prefix=$PWD/../ARM_LIBS ./configure
make -j`getconf _NPROCESSORS_ONLN`
make install

