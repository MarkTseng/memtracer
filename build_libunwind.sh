#!/bin/bash
cd libunwind 
make clean
#autoreconf -i
./autogen.sh
./configure --host=arm-linux-gnueabihf --prefix=$PWD/../ARM_LIBS/ CFLAGS="-U_FORTIFY_SOURCE -DDEBUG -g" --enable-maintainer-mode --enable-debug --enable-debug-frame
make -j`getconf _NPROCESSORS_ONLN`
make install 
