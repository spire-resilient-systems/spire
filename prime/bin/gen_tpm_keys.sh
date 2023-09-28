#!/bin/bash

mkdir -p tpm_keys

openssl dhparam -outform PEM -out tpm_keys/dhparam.pem 4096

# Change this to the number of nodes in the network
#
#       Note: for security reasons, we recommend running this script
#            offline and moving the private key to to each node individually.
#            All public keys should be placed on all nodes.

for i in {1..30}
do
  openssl genrsa -out tpm_keys/tpm_private$i.pem 3072
  openssl rsa -in tpm_keys/tpm_private$i.pem -out tpm_keys/tpm_public$i.pem -outform PEM -pubout
done


