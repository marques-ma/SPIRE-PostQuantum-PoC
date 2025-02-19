#!/bin/bash

# set the spire path
export SPIREPATH="/home/byron/artifacts/SPIRE-PostQuantum-PoC"

# set the PQ digital signature algorithm to be used
# reference: https://github.com/open-quantum-safe/oqs-provider/blob/main/ALGORITHMS.md
export PQALGO="p384_dilithium3"

reset_spire() {
     kill -9 $(ps -ef | grep "spire-agent" | grep -v grep | awk '{print $2}')
     kill -9 $(ps -ef | grep "spire-server" | grep -v grep | awk '{print $2}')
     rm -rf $SPIREPATH/.data
}
reset_spire
sleep 1

# Start the SPIRE Server as a background process
start_spire_server () {
    echo "Starting spire-server..."
    sleep 1
    $SPIREPATH/bin/spire-server run -config $SPIREPATH/conf/server/server.conf &
    sleep 2
}
start_spire_server

# Generate a one time Join Token
generate_jointoken () {
echo "Generating token..."
sleep 1
tmp=$( $SPIREPATH/bin/spire-server token generate -spiffeID spiffe://example.org/host)
echo $tmp
token=${tmp:7}
echo -e "Generated token: $token. \n Ready to start a new agent."
}

# Start the SPIRE Agent as a background process using the join token
start_spire_agent () {

    generate_jointoken
    echo "Starting spire-agent..."
    sleep 1
    $SPIREPATH/bin/spire-agent run -joinToken $token -config $SPIREPATH/conf/agent/agent.conf &
    token=''
}
start_spire_agent

# Optionally, use the command bellow to create a registry entry to your user. Modify according:
# $SPIREPATH/bin/spire-server entry create \
#     -parentID spiffe://example.org/host \
#     -spiffeID spiffe://example.org/workloadID \
#     -selector unix:user:<username>
