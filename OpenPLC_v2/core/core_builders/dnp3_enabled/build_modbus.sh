#!/bin/bash

# DNP3 local install location
DNP3_DIR=../dnp3_build/install
DNP3_LIBS="$DNP3_DIR/lib/libasiodnp3.a $DNP3_DIR/lib/libasiopal.a $DNP3_DIR/lib/libopendnp3.a $DNP3_DIR/lib/libopenpal.a"

cd core
echo Generating object files...
g++ -std=gnu++11 -I ./lib -I $DNP3_DIR/include -c Config0.c -Wno-narrowing
g++ -std=gnu++11 -I ./lib -I $DNP3_DIR/include -c Res0.c -Wno-narrowing
echo Generating glueVars.cpp
./glue_generator
echo Compiling main program
g++ -std=gnu++11 *.cpp *.o -o openplc -I ./lib -I $DNP3_DIR/include -pthread -fpermissive `pkg-config --cflags --libs libmodbus` $DNP3_LIBS -Wno-narrowing
cd ..
