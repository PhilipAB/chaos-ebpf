#!/bin/bash

# we need to ensure that the node name is provided as an argument
if [ "$#" -lt 1 ]; then
    echo "Usage: $0 <node-name> [flags]"
    exit 1
fi

# Let's create a chaos scenario which is simulating the mobile handover of a device
# We do this for the ethernet network on the host
# To do so we also want to restrict this process to a specific port and network protocol
# This prevents side effects to the rest of our system
node_name="$1"
interface="ETH"
namespace="HOST"
enable_ipv4=true
enable_ipv6=true
enable_icmp=false
enable_tcp=true
enable_udp=false
ipv4_range="127.1.1.1"
ipv4_mask="255.255.255.255"
port=5201

shift # shift arguments to the left to process optional ones

# parse optional JSON payload parameters
while [ "$#" -gt 0 ]; do
    case "$1" in
        --port)
            port=$2
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
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# a function to enable or update bandwidth
update_bandwidth() {
    local bandwidth=$1 # Bandwidth in bytes per second
    echo "Updating bandwidth to $bandwidth B/s on $node_name"
    local json_payload="{\"filter\": {\"interface\": \"$interface\", \"namespace\": \"$namespace\", \"enable_ipv4\": $enable_ipv4, \"enable_ipv6\": $enable_ipv6, \"enable_icmp\": $enable_icmp, \"enable_tcp\": $enable_tcp, \"enable_udp\": $enable_udp, \"ipv4_range\": [\"$ipv4_range\"], \"ipv4_mask\": \"$ipv4_mask\", \"ports\": [\"$port\"]}, \"bandwidth\": $bandwidth, \"traffic_direction\": false}"
    sudo docker run --network host fullstorydev/grpcurl -plaintext -d "$json_payload" $(kubectl get pods -o wide | grep "$node_name" | awk '{print $6}' | head -n 1):8080 networkfilter.NetworkFilter/EnableBandwidthManager
}

# a function to disable bandwidth management
disable_bandwidth() {
    echo "Disabling bandwidth management on $node_name"
    local json_payload="{\"interface\": \"$interface\", \"namespace\": \"$namespace\", \"traffic_direction\": false}"
    sudo docker run --network host fullstorydev/grpcurl -plaintext -d "$json_payload" $(kubectl get pods -o wide | grep "$node_name" | awk '{print $6}' | head -n 1):8080 networkfilter.NetworkFilter/DisableBandwidthManager
}

# a function to set packet loss
set_packet_loss() {
    local drop_rate=$1 # Packet drop rate in percentage
    echo "Setting packet loss to $drop_rate% on $node_name"
    local json_payload="{\"filter\": {\"interface\": \"$interface\", \"namespace\": \"$namespace\", \"enable_ipv4\": $enable_ipv4, \"enable_ipv6\": $enable_ipv6, \"enable_icmp\": $enable_icmp, \"enable_tcp\": $enable_tcp, \"enable_udp\": $enable_udp, \"ipv4_range\": [\"$ipv4_range\"], \"ipv4_mask\": \"$ipv4_mask\", \"ports\": [\"$port\"]}, \"drop_rate\": $drop_rate}"
    sudo docker run --network host fullstorydev/grpcurl -plaintext -d "$json_payload" $(kubectl get pods -o wide | grep "$node_name" | awk '{print $6}' | head -n 1):8080 networkfilter.NetworkFilter/EnableNetworkFilter
}

# a function to disable packet loss
disable_packet_loss() {
    echo "Disabling packet loss generator on $node_name"
    local json_payload="{\"interface\": \"$interface\", \"namespace\": \"$namespace\"}"
    sudo docker run --network host fullstorydev/grpcurl -plaintext -d "$json_payload" $(kubectl get pods -o wide | grep "$node_name" | awk '{print $6}' | head -n 1):8080 networkfilter.NetworkFilter/DisableNetworkFilter
}

# start bw manager with 50Mbps
update_bandwidth 50000000
sleep 15s

# reduce bw to 20Mbps
update_bandwidth 20000000
sleep 15s

# further reduce to 10Mbps
update_bandwidth 10000000
sleep 15s

# ... reduce to 1Mbps
update_bandwidth 1000000
sleep 15s

# disable bandwidth management and set packet loss to 100%
disable_bandwidth
sleep 1s # short buffer to ensure command is processed (since it's async)
set_packet_loss 100
sleep 15s
# we regained connection ... let's disable the packet loss generator
disable_packet_loss
sleep 1s # short buffer to ensure command is processed (since it's async)

# finally, enable bandwidth management again at 5Mbps
update_bandwidth 5000000

sleep 15s

# finish chaos scenario
disable_bandwidth
