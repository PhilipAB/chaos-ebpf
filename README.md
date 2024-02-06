# chaos-ebpf

Welcome to chaos-ebpf, a powerful and flexible solution designed to enhance the reliability and resilience of distributed systems, particularly within Kubernetes environments. Developed as part of a Master Thesis at [Darmstadt University of Applied Sciences](https://h-da.de/) (h_da), this tool leverages eBPF (Extended Berkeley Packet Filter) to provide a seamless and sophisticated method for simulating real-world networking chaos scenarios without requiring deep knowledge of eBPF.

## Features
- **Comprehensive Chaos Scenarios**: Simulate network chaos directly on Kubernetes nodes, including bandwidth management, packet loss/drop, latency/jitter, and duplication. This tool is designed to test the robustness of your distributed systems under various conditions.
- **gRPC Interface**: Utilize a straightforward gRPC API for executing chaos experiments. Scripts can easily interact with this tool, making it accessible for users with varying technical backgrounds.
- **Containerized Solution**: Packaged as a container image, this tool is perfectly suited for Kubernetes environments, ensuring easy deployment and scalability.
- **Advanced Filtering**: Apply filters to your chaos experiments, including port ranges, IP ranges, and protocols, to tailor the chaos to your specific test scenarios.
- **Important Considerations Security and Safety**: This tool operates in a privileged container to perform its functions. This approach allows it to introduce network chaos at the node level but also requires careful handling to prevent unintended effects. It is strongly recommended for use in non-critical test environments only and not in production.
- **Knowledge Requirements**: While the tool abstracts away the complexities of eBPF, a solid understanding of networking is necessary to use it effectively and safely.
- **Current Limitations**: This tool is only a prototype and still in beta stage. Some functions were only implemented partly and need to be refined in the future. Before releasing a 1.0 version, the chaining of eBPF needs to be implemented and thus supported fully. Moreover, the packet corruption function is under development due to challenges with the eBPF verifier. I am actively troubleshooting this issue.

## Current release
The publicly available and offical container image can be found [here](https://hub.docker.com/repository/docker/philipab/chaos-ebpf). The newest release tag is [0.3.0-beta](https://hub.docker.com/layers/philipab/chaos-ebpf/0.3.0-beta/images/sha256-0672b428c2dd5c20b1097fb586778c9bab03ca0f2906635256006fc4a9d0af29).

## Prerequisites

This tool was build and run on an ARM64-based virtual machine. Hence its functionality can only be ensured on ARM64-based systems. 

## Semi-automatic installation (k3s)
This tool was tested in a multinode [k3s](https://k3s.io/) Kubernetes cluster on Google cloud. To kickstart the project and to circumvent a complicated installation process, cloud-init scripts were developed and are available [here](/cloud-init/). The following steps are describing how to configure and use these cloud-init scripts.

1. Generate a new public/private key pair (e. g. RSA).
2. In [master-config](/cloud-init/master-config), replace line 12 (`<robot-ssh-key>`) with your newly generated public key.
3. Use the [master-config](/cloud-init/master-config) to start the master node.
4. Spin up or connect to a worker node, to configure a new vm image/snapshot.
5. Switch into the users home directory that executes cloud-init scripts on your machine (e. g. root directory).
6. Create (`mkdir .ssh`) and/or switch (`cd .ssh`) into the `.ssh`-directory.
7. Create a new private key file: `cat > id_rsa`.
8. Paste your private key (from step 1) and press CTRL+D.
9. Create (`cat > config`) or edit (`vim config`) the ssh-config file.
10. Paste the following content into the ssh-config file. Point the host ip to your master node and edit the users home directory (in this example root) if necessary: 
```
Host <Host-IP>
    IdentityFile /root/.ssh/id_rsa
    User robot
    StrictHostKeyChecking no
```
11. Build a vm image/snapshot from your worker node.
12. Finally in the [worker-config](./cloud-init/worker-config) replace this part of the code `cube${CUBE_NUMBER}-head.local` (2 occurences) by your master node's ip.
13. Now you are able to spin up worker nodes by simply starting them, using your newly created vm image/snapshot along with the cloud-init configuration

## Usage
To use this tool, it is recommended to install docker on your client machine (e.g. via [install docker on Ubuntu](https://docs.docker.com/engine/install/ubuntu/)).
This simplifies the usage of [gRPCurl](https://github.com/fullstorydev/grpcurl), although it is not required and also possible to install separately if desired. 

### Running a gRPC client request

Since this is a tool for non-critical testing environments only, our gRPC service runs with reflection. Hence, we can use gRPCurl to query our API this way:
```
sudo docker run --network host fullstorydev/grpcurl -plaintext -d "<json-payload>" <pod-ip>:8080 networkfilter.NetworkFilter/<RPC name>
```

### Running example scripts

Examples how to use and enable/disable the chaos functions can be found in the [scripts folder](/scripts/).\
**Note**: To execute a script it is required to provide at least a node name plus some optional parameters, e.g.:
```
sudo sh tshaper_req_enable.sh <node-name>
```

### Veryfying ICMP related functionality

To verify the functionality for ICMP traffic we can simply use the `ping` command. By using the `-i` option, we can specify the interval of our requests and by using the `-s` option the payload size.

**Beware(!)**, in addition to the payload specified, the overall packet size will increment due to the inclusion of various headers:
- 8-byte ICMP header 
- 20-byte IP header
- 14-byte ethernet header

It is important to note that these values may slightly vary upwards, e.g. if some IP options are provided.

An example for a ping command:
```
sudo ping -i 0.1 -s 100 <target-ip-address> 
```

### Veryfying TCP/UDP related functionality

To verify chaos functionality for TCP/UDP traffic, it is recommended to use the tool [iPerf3](https://github.com/esnet/iperf). It can easily be installed on Ubuntu by running the following commands:

1. Update your package list: `sudo apt update`
2. Install iPerf3: `sudo apt install -y iperf3`
3. Verify installation: `iperf3 -v`

Now by running the following command we can start a TCP/UDP server on our target node for chaos operations:
```
sudo iperf3 -s -p <port nr>
```

Our client can now decide whether it connects via TCP or UDP. Connecting via TCP is the default option and works like this:
```
iperf3 -c <target node ip> -t 30 -p <port nr> -b 1000000
```
Here is a brief explanation about the flags:
- `-c`: Client option
- `-t`: Duration of client connection
- `-p`: Port number
- `-b`: Transmitted bit size per second

To target the UDP server as a client, we can simply add the `-u` flag like this:
```
iperf3 -c <target node ip> -t 30 -p <port nr> -b 1000000 -u
```

## Roadmap
There are some loose targets which are planned as next steps. However nothing is set in stone yet. So feel free to recommend any changes, feature requests or report any bugs that you notice. Current plans are:
1. Fix packet corruption functionality.
2. Enable chaining of eBPF programs for all chaos functions.
3. Release version 1.0.0(-beta)
4. Further testing...

### About Testing ...

To enhance the overall quality and reliability of our tool, it is necessary to expand our testing coverage. Currently, the tool has undergone testing exclusively within a k3s Kubernetes cluster hosted on Google Cloud, utilizing ARM64-based VMs. The primary objective of these tests was to ascertain the general functionality of our chaos functions. Moving forward, it is critical to conduct comprehensive testing across a diverse range of parameters and documenting the process to confirm the effective operation of the filter.

To facilitate this, the implementation of a testing pipeline would be highly beneficial. Such a pipeline could be activated by pull requests, among other triggers, to systematically verify functionality. It is essential to acknowledge the unique requirements of testing in this context. Specifically, the necessity of creating VMs to thoroughly test the tool, given its reliance on eBPF technology.

Additionally, there is a pressing need to rigorously test the tool's response to invalid parameters. This involves determining whether the program can reliably handle and mitigate issues arising from incorrect or inappropriate parameter inputs. Ensuring robust handling of such scenarios is crucial for maintaining the tool's integrity and user trust.

### Further improving user experience ...

At the moment it is necessary for users to create bash scripts and use a thirdparty tool like gRPCurl to create chaos scenarios. This is a great way to abstract the eBPF complexity. But not every kubernetes administrator is necessarily a developer.

Hence, it may be desirable (especially for Kubernetes administrators) to simply define and create a Kubernetes resource which automatically invokes the gRPC request with the desired parameters.

How could this be achieved? We could create one or multiple Custom Resource Definition(s) (CRDs) on our system which are describing the target chaos function(s) and its parameters. Then, by implementing a custom controller, we could watch for events on those CRDs and query our API accordingly. This would for example work on creation but also on update or deletion of our CRDs.

This strategy removes the necessity for external tools like `gRPCurl` and offers clear-cut templates to create chaos scenarios.

## Contributing
Contributions to this repository are generally accepted. To contribute, please create a pull request and state what your pull request does and why it is needed.

## License
This project is licensed under [Apache License Version 2.0](/LICENSE) **except** for the [eBPF-folder](/ebpf/). For further details about the [eBPF-folder](/ebpf/) licensing, please refer to its [license](/ebpf/LICENSE) and [Readme.md file](/ebpf/Readme.md).