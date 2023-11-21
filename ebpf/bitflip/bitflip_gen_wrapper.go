package bitflip

import "github.com/cilium/ebpf"

// This is a wrapper class which publicly exposes the functions/types that we need in other places within our code

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang bitflipGen bitflip_gen.c -- -I../config -I../linux

func LoadBitflipGenObjectsWrapper(obj interface{}, opts *ebpf.CollectionOptions) error {
	return loadBitflipGenObjects(obj, opts)
}

type BitflipGenObjectsWrapper struct {
	bitflipGenObjects
}
