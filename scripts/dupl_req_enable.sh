#!/bin/bash

# default values for JSON payload parameters
interface="lo"
namespace="HOST"
enable_ipv4=false
enable_ipv6=true
enable_icmp=true
enable_tcp=true
enable_udp=true
ipv4_range="127.0.0.1"
ipv4_mask="255.255.255.255"
duplication_rate=5
traffic_direction=false

# check the number of arguments provided
if [ "$#" -lt 1 ]; then
    echo "Usage: $0 <node-name> [flags]"
    exit 1
fi

node_name=$1
shift # shift arguments to the left to process optional ones

# parse optional JSON payload parameters
while [ "$#" -gt 0 ]; do
    case "$1" in
        --interface)
            interface=$2
            shift 2
            ;;
        --namespace)
            namespace=$2
            shift 2
            ;;
        --enable-ipv4)
            enable_ipv4=$2
            shift 2
            ;;
        --enable-ipv6)
            enable_ipv6=$2
            shift 2
            ;;
        --enable-icmp)
            enable_icmp=$2
            shift 2
            ;;
        --enable-tcp)
            enable_tcp=$2
            shift 2
            ;;
        --enable-udp)
            enable_udp=$2
            shift 2
            ;;
        --ipv4-range)
            ipv4_range=$2
            shift 2
            ;;
        --ipv4-mask)
            ipv4_mask=$2
            shift 2
            ;;
        --duplication_rate)
            duplication_rate=$2
            shift 2
            ;;
        --traffic_direction)
            traffic_direction=$2
            shift 2
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# test if the node exists
if ! kubectl get nodes "$node_name" > /dev/null 2>&1; then
    echo "Node '$node_name' not found"
    exit 1
fi

# retrieve pod ip on node
pod_ip=$(kubectl get pods -o wide | grep "$node_name" | awk '{print $6}' | head -n 1)

if [ -z "$pod_ip" ]; then
    echo "No pods found on node $node_name"
    exit 1
fi

echo "Pod IP: $pod_ip"

# dynamically constructing JSON payload 
json_payload="{\"filter\": {\"interface\": \"$interface\", \"namespace\": \"$namespace\", \"enable_ipv4\": $enable_ipv4, \"enable_ipv6\": $enable_ipv6, \"enable_icmp\": $enable_icmp, \"enable_tcp\": $enable_tcp, \"enable_udp\": $enable_udp, \"ipv4_range\": [\"$ipv4_range\"], \"ipv4_mask\": \"$ipv4_mask\"}, \"duplication_rate\": $duplication_rate, \"traffic_direction\": $traffic_direction}"

# query the gRPC-Service
sudo docker run --network host fullstorydev/grpcurl -plaintext -d "$json_payload" $pod_ip:8080 networkfilter.NetworkFilter/EnableDuplicationGen

echo "Command executed on pod: $node_name"
