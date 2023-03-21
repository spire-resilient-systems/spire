#!/bin/bash

INSTALL_LOC=./install

# NON-STANDARD GCC LOCATION: Set C_LOC and CXX_LOC to your gcc and g++ >= 4.9
# and pass these options to cmake (uncomment following 3 lines and comment
# final line)
#C_LOC=/toolchains/bin/gcc
#CXX_LOC=/toolchains/bin/g++

#cmake ../opendnp3 -DSTATICLIBS=ON -DCMAKE_C_COMPILER=$C_LOC -DCMAKE_CXX_COMPILER=$CXX_LOC -DCMAKE_INSTALL_PREFIX=$INSTALL_LOC && make && make install

# If your normal system gcc/g++ version is >= 4.9, you can just use:
cmake ../opendnp3 -DSTATICLIBS=ON -DCMAKE_INSTALL_PREFIX=$INSTALL_LOC && make && make install
