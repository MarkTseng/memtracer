#!/bin/bash
cd elfutils
make clean
autoreconf -f -i
./configure --host=arm-linux-gnueabihf --prefix=$PWD/../ARM_LIBS/ --with-zlib CFLAGS="-I$PWD/../ARM_LIBS/include"  LDFLAGS="-L$PWD/../ARM_LIBS/lib -Wl,-rpath,$PWD/../ARM_LIBS/lib"
make -j`getconf _NPROCESSORS_ONLN`
make install
