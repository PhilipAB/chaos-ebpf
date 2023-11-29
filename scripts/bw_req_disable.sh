#!/bin/bash

# default values
interface="LO"
namespace="HOST"
traffic_direction=false

# check the number of arguments provided
if [ "$#" -lt 1 ] || [ "$#" -gt 4 ]; then
    echo "Usage: $0 <node-name> [interface] [namespace] [traffic-direction]"
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

# override traffic-direction (if provided)
if [ ! -z "$4" ]; then
    traffic_direction=$4
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

# disable bw manager
json_payload="{\"interface\": \"$interface\", \"namespace\": \"$namespace\", \"traffic_direction\": $traffic_direction}"
sudo docker run --network host fullstorydev/grpcurl -plaintext -d "$json_payload" $pod_ip:8080 networkfilter.NetworkFilter/DisableBandwidthManager

echo "Command executed on pod: $node_name"