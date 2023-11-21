package bwmanager

import "github.com/cilium/ebpf"

// This is a wrapper class which publicly exposes the functions/types that we need in other places within our code
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang bwmanager bwmanager.c -- -I../config -I../linux

func LoadBwObjectsWrapper(obj interface{}, opts *ebpf.CollectionOptions) error {
	return loadBwmanagerObjects(obj, opts)
}

type BwObjectsWrapper struct {
	bwmanagerObjects
}

type XFSMTableKeyWrapper struct {
	bwmanagerXFSMTableKey
}

type XFSMTableLeafWrapper struct {
	bwmanagerXFSMTableLeaf
}
