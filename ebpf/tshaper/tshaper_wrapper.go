package tshaper

import "github.com/cilium/ebpf"

// This is a wrapper class which publicly exposes the functions/types that we need in other places within our code

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang tshaper tshaper.c -- -I../config -I../linux

func LoadTshaperObjectsWrapper(obj interface{}, opts *ebpf.CollectionOptions) error {
	return loadTshaperObjects(obj, opts)
}

type TshaperObjectsWrapper struct {
	tshaperObjects
}
