package delay

import "github.com/cilium/ebpf"

// This is a wrapper class which publicly exposes the functions/types that we need in other places within our code

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang delayGen delay_gen.c -- -I../config -I../linux

func LoadDelayGenObjectsWrapper(obj interface{}, opts *ebpf.CollectionOptions) error {
	return loadDelayGenObjects(obj, opts)
}

type DelayGenObjectsWrapper struct {
	delayGenObjects
}
