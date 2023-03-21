#!/bin/bash

PRIME_DIR=../prime
SCADA_DIR=../

# Print out usage information
function print_usage {
    printf "\n%s\n\n" "This program recompiles the code to update it after changing def.h files."
    printf "%s\n%s\n%s\n\n" "Usage: ./`basename $0`" \
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

# Compile Prime/Spire
(cd $PRIME_DIR/src && make cleaner; make; exit)
(cd $SCADA_DIR && make clean; make; exit)
