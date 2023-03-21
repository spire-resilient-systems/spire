#!/bin/bash

mkdir -p keys

openssl dhparam -outform PEM -out keys/dhparam.pem 2048

# Change this to the number of nodes in the network
#
#       Note: for security reasons, we recommend running this script
#            offline and moving the private key to to each node individually.
#            All public keys should be placed on all nodes.

for i in {1..10}
do
  openssl genrsa -out keys/private$i.pem 1024
  openssl rsa -in keys/private$i.pem -out keys/public$i.pem -outform PEM -pubout
done
