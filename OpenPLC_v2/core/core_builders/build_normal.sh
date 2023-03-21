#!/bin/bash

# NON-STANDARD GCC LOCATION: Set CXX_LOC to your g++ >= 4.9 and uncomment CXXLIB
#CXX_LOC=/toolchains/bin/g++
#CXXLIB=-Wl,-rpath,/toolchains/lib64
CXX_LOC=g++

# DNP3 location
DNP3_DIR=../../opendnp3/opendnp3_build/install

cd core
echo Generating object files...
$CXX_LOC -std=gnu++11 -I ./lib -I $DNP3_DIR/include -c Config0.c
$CXX_LOC -std=gnu++11 -I ./lib -I $DNP3_DIR/include -c Res0.c
echo Generating glueVars.cpp
./glue_generator
echo Compiling main program
$CXX_LOC -std=gnu++11 *.cpp *.o -o openplc -I ./lib -I $DNP3_DIR/include -pthread -fpermissive $DNP3_DIR/lib/libasiodnp3.a $DNP3_DIR/lib/libasiopal.a $DNP3_DIR/lib/libopendnp3.a $DNP3_DIR/lib/libopenpal.a -lrt $CXXLIB
cd ..
