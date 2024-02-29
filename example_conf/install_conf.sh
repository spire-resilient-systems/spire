#!/bin/bash

EXPECTED_ARGS=1
SPINES_DIR=../spines
PRIME_DIR=../prime
SCADA_DIR=../

# Print out usage information
function print_usage {
    printf "\n%s\n%s\n\n" "This program copies the configuration files in the specified" \
                          "directory <conf_dir> to the right locations in Spire."
    printf "%s\n%s\n%s\n\n" "Usage: ./`basename $0` <conf_dir>" \
                            "Options:" \
                            "  -h : print this help and exit"
    exit
}

# Validate options
while getopts ":h" opt
do
    case $opt in
        h)
            print_usage
            ;;
        \?)
            printf "\nInvalid option"
            print_usage
            ;;
    esac
done

if [ $# -ne $EXPECTED_ARGS ]
then
    print_usage
fi

Confdir=$1

if [ ! -d $Confdir ]
then
    printf "\nError: directory $Confdir does not exist\n"
    print_usage
fi

# Copy configuration files to the right locations
cp $Confdir/spines_int.conf $SPINES_DIR/daemon/spines_int.conf         && \
cp $Confdir/spines_ext.conf $SPINES_DIR/daemon/spines_ext.conf         && \
cp $Confdir/scada_def.h $SCADA_DIR/common/def.h                        && \
cp $Confdir/address.config $PRIME_DIR/bin/address.config               && \
cp $Confdir/spines_address.config $PRIME_DIR/bin/spines_address.config && \
cp $Confdir/prime_def.h $PRIME_DIR/src/def.h                           && \
cp $Confdir/config.json $SCADA_DIR/config/config.json                  

if [ -f $Confdir/spines_ctrl.conf ]
then
	cp $Confdir/spines_ctrl.conf $SPINES_DIR/daemon/spines_ctrl.conf      
fi 
