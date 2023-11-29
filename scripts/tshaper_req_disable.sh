#!/bin/bash

# default values
interface="LO"
namespace="HOST"

# check the number of arguments provided
if [ "$#" -lt 1 ] || [ "$#" -gt 3 ]; then
    echo "Usage: $0 <node-name> [interface] [namespace]"
    exit 1
fi

node_name=$1

# override interface (if provided)
if [ ! -z "$2" ]; then
    interface=$2
fi

# override namespace (if provided)
if [ ! -z "$3" ]; then
    namespace=$3
fi

# test if the node exists
if ! kubectl get nodes "$node_name" > /dev/null 2>&1; then
    echo "Node '$node_name' not found"
    exit 1
fi

# get pod ip on node
pod_ip=$(kubectl get pods -o wide | grep "$node_name" | awk '{print $6}' | head -n 1)

if [ -z "$pod_ip" ]; then
    echo "No pods found on node $node_name"
    exit 1
fi

echo "Pod IP: $pod_ip"

# disable delay generator
json_payload="{\"interface\": \"$interface\", \"namespace\": \"$namespace\"}"
sudo docker run --network host fullstorydev/grpcurl -plaintext -d "$json_payload" $pod_ip:8080 networkfilter.NetworkFilter/DisableNetworkFilter

echo "Command executed on pod: $node_name"