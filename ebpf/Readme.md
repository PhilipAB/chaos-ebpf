# eBPF

In this folder, all files are licensed under [GPL-2.0](/ebpf/LICENSE). An exception to this are our go-files, which are licensed like the rest of the repository under [Apache License Version 2.0](/LICENSE).

## Why are our eBPF programs licensed under GPL-2.0?

The decision to use [GPL-2.0](/ebpf/LICENSE) for our eBPF programs, all related C-code and compiled byte code is due to the interaction with the Linux kernel, which is also GPL-licensed. Especially the usage of some or all bpf_helper functions, linux types etc. is requiring us to license this code this way. Moreover some parts of our C-code and type definitions were inspired by [GPL-2.0](/ebpf/LICENSE) code from the following repositories:
- [xdp-tools](https://github.com/xdp-project/xdp-tools)
- [tbpoc-bpf](https://github.com/qmonnet/tbpoc-bpf)
- [linux](https://github.com/torvalds/linux)

Usage of these repositories is directly referenced within the code.

## Why is the userspace code not required to be licensed under GPL-2.0?

Our userspace application interfaces with Linux kernel components indirectly by using system calls through the cilium/ebpf library, e.g. to activate our eBPF programs. During this process, we encountered a specific exception, as detailed [here](https://github.com/torvalds/linux/blob/master/LICENSES/exceptions/Linux-syscall-note):
```
This copyright does *not* cover user programs that use kernel
 services by normal system calls - this is merely considered normal use
 of the kernel, and does *not* fall under the heading of "derived work".
```